/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.datalake.DatalakeStorageException;
import com.michelin.cert.redscan.utils.models.HttpService;
import com.michelin.cert.redscan.utils.models.Vulnerability;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import org.apache.logging.log4j.LogManager;
import org.json.JSONObject;

import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * RedScan scanner main class.
 *
 * @author Maxime ESCOURBIAC
 * @author Sylvain VAISSIER
 * @author Maxence SCHMITT
 */
@SpringBootApplication
public class SecuritytxtScanApplication {

  //Only required if pushing data to queues
  private final RabbitTemplate rabbitTemplate;
  
  @Autowired
  private DatalakeConfig datalakeConfig;

  /**
   * Constructor to init rabbit template. Only required if pushing data to queues
   *
   * @param rabbitTemplate Rabbit template.
   */
  public SecuritytxtScanApplication(RabbitTemplate rabbitTemplate) {
    this.rabbitTemplate = rabbitTemplate;
  }

  /**
   * RedScan Main methods.
   *
   * @param args Application arguments.
   */
  public static void main(String[] args) {
    SpringApplication.run(SecuritytxtScanApplication.class, args);
  }

  /**
   * Datalake shortcut for upserting
   * @param domain The domain
   * @param port The port...
   * @param res Valid , invalid, notFound
   */
  public void insertResult(String domain, String port,String res) {
    
    try {
      
      datalakeConfig.upsertHttpServiceField(domain, port, "securitytxt", res);
    } catch (DatalakeStorageException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Data lake storage exception %s", ex.toString()));
    }
  }
  /**
   * Sending Alert to the good channel.
   * @param domain The domain refering the vulnerbaility
   * @param message should be the message of the vulnerability
   * @param vulnName should be the conernend vuln (TLS activated, heartbleed..)
   * @param sev The sevrity of the vuln (HIGH=1,MEDIUM=3,LOW=4,INFO=5)
   * @param vulnData The JSON objcet representign the vulnerbaility to upsert.
   */
  public void alarm(String domain, String message, String vulnName, int sev, JSONObject vulnData) {
    Vulnerability vuln = new Vulnerability(Vulnerability.generateId("redscan-securitytxt", domain, vulnName),
        sev,
        String.format("[%s] failed on security text %s", domain,vulnName),
        String.format("Security text failed: %s",vulnName, message, vulnData),
        String.format("%s/.well-known/security.txt",domain),
        "redscan-securitytxt"
        );
    
    rabbitTemplate.convertAndSend(RabbitMqConfig.FANOUT_VULNERABILITIES_EXCHANGE_NAME, "", vuln.toJson());
  }
  
  /**
   * Compare securtiy txt content
   * @param object JSON object from contentParser
   * @return Acknowled Boolean true if secrutiy txt is valid.
   */
  public boolean isValid(JSONObject object) {
    if ((object.has("Contact"))  
        && (object.has("Encryption"))  
        && (object.has("Hiring"))  
        && (object.has("Policy"))) {
      if ((object.get("Contact").toString().contains("cert[at]michelin.com"))  
          && (object.get("Encryption").toString().contains("https://cert.michelin.com"))  
          && (object.get("Hiring").toString().contains("https://careers.michelin.com"))  
          && (object.get("Policy").toString().contains("https://cert.michelin.com"))) {
        return true;
      }
    }
    return false;
  }
  /**
   * Check Securtiy txt content.
   * @param url refer to the file url path
   * @return txtJson formated JSOn security txt file.
   */
  public JSONObject contentParser(URL url) {
    JSONObject txtJson = new JSONObject();
    LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("Parsing content"));
    try {
      URLConnection hurl = url.openConnection();
      hurl.setRequestProperty("Content-Type", "text/plain"); 
      BufferedReader in = new BufferedReader(new InputStreamReader(hurl.getInputStream()));
      if (in != null ) {
        String[] content;
        String inputLine;
        txtJson.put("location", url);
        while (( inputLine = in.readLine()) != null) {
          if (!inputLine.equals(System.getProperty("line.separator"))) {
            String key = inputLine.split(":")[0];
            String value = inputLine.split(":")[1];
            txtJson.put(key, value);
          }
        }
      } 
      
    } catch (MalformedURLException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("%s thrown Exption : %s",ex.getClass(),ex.toString()));
    } catch (IOException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("%s thrown Exption : %s",ex.getClass(),ex.toString()));
    }
    return txtJson;
  }
  /**
   * Message executor.
   *
   * @param message Message received.
   */
  @RabbitListener(queues = {RabbitMqConfig.QUEUE_HTTP_SERVICES})
  public void receiveMessage(String message) {
    HttpService serviceMessage = new HttpService(message);
    JSONObject result;
    LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Checking Security text on : %s", serviceMessage.getDomain()));
    try {
      String wellKnowUrl = String.format("%s://%s:%s/.well-known/security.txt",
              serviceMessage.getProtocol(),
              serviceMessage.getDomain(),
              serviceMessage.getPort());
      String rootUrl = String.format("%s://%s:%s/security.txt",
              serviceMessage.getProtocol(),
              serviceMessage.getDomain(),
              serviceMessage.getPort());
      URL wk = new URL(wellKnowUrl);
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("locating content"));
      HttpURLConnection http = (HttpURLConnection) wk.openConnection();
      http.setRequestProperty("Content-Type", "text/plain");
      http.connect();
      int responseCode = http.getResponseCode();
      if (responseCode == 200) {
        result = contentParser(wk);
        if (isValid(result)) {
          insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), "valid");
        } else {
          insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), "invalid");
          alarm(serviceMessage.getDomain(), "invalid security txt", "invalidFile", 5, result);
        }
      } else {
        LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("locating content under root directory"));
        URL root = new URL(rootUrl);
        http = (HttpURLConnection) root.openConnection();
        int rootResponseCode = http.getResponseCode();
        if (rootResponseCode == 200) {
          result = contentParser(root);
          if (isValid(result)) {
            insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), "valid");
          } else {
            insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), "invalid");
            alarm(serviceMessage.getDomain(), "invalid security txt", "invalidFile", 5, result);
          }
        } else {
          alarm(serviceMessage.getDomain(),"Security.txt not found", "notFound", 5, null);
          insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), "notFound");
        }
        
      }      
    } catch (MalformedURLException | SocketException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("%s thrown Exption : %s",ex.getClass(),ex.toString()));
    } catch (IOException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("%s thrown Exption : %s",ex.getClass(),ex.toString()));
    }
    
  }

}
