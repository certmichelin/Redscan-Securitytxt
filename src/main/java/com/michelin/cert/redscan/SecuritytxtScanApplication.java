/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.datalake.DatalakeStorageException;
import com.michelin.cert.redscan.utils.models.HttpService;
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
   * @param res either the content of the file or notFound
   */
  public void insertResult(String domain, String port,String res) {
    
    try {
      datalakeConfig.upsertHttpServiceField(domain, port, "securitytxt", res);
    } catch (DatalakeStorageException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Data lake storage exception %s", ex.toString()));
    }
  }
   
  /**
   * Check Securtiy txt content.
   * @param url refer to the file url path
   * @return txtJson formated JSOn security txt file.
   */
  public String contentParser(URL url) {
    JSONObject txtJson = new JSONObject();
    LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("Parsing content"));
    StringBuilder content = new StringBuilder();
    try {
      URLConnection hurl = url.openConnection();
      hurl.setRequestProperty("Content-Type", "text/plain"); 
      BufferedReader in = new BufferedReader(new InputStreamReader(hurl.getInputStream()));
      if (in != null ) {
        String inputLine;
        while (( inputLine = in.readLine()) != null) {
          if (!inputLine.equals(System.getProperty("line.separator"))) {
            content.append(inputLine);
          }
        }
      } 
      
    } catch (MalformedURLException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("%s thrown Exption : %s",ex.getClass(),ex.toString()));
    } catch (IOException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("%s thrown Exption : %s",ex.getClass(),ex.toString()));
    }
    return content.toString();
  }
  /**
   * Message executor.
   *
   * @param message Message received.
   */
  @RabbitListener(queues = {RabbitMqConfig.QUEUE_HTTP_SERVICES})
  public void receiveMessage(String message) {
    HttpService serviceMessage = new HttpService(message);
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
        insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), contentParser(wk));       
      } else {
        LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("locating content under root directory"));
        URL root = new URL(rootUrl);
        http = (HttpURLConnection) root.openConnection();
        int rootResponseCode = http.getResponseCode();
        if (rootResponseCode == 200) {
          insertResult(serviceMessage.getDomain(), serviceMessage.getPort(), contentParser(root));
        } else {
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
