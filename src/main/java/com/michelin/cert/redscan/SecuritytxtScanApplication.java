/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.datalake.DatalakeStorageException;
import com.michelin.cert.redscan.utils.models.HttpService;

import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import org.apache.logging.log4j.LogManager;

import org.springframework.amqp.rabbit.annotation.RabbitListener;
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

  @Autowired
  private DatalakeConfig datalakeConfig;


  /**
   * RedScan Main methods.
   *
   * @param args Application arguments.
   */
  public static void main(String[] args) {
    SpringApplication.run(SecuritytxtScanApplication.class, args);
  }
   
  /**
   * Check that the file is at minima a security.txt.
   * @param content is the content of the response body. Shloud be a securitytxt
   * @return boolean with indicate if the file is possibly a security.txt
   */
  public boolean contentCheck(String content) {
    //String[] unsigned_content = {"Contact:", "Encryption", "Policy", "Acknowledgments", "Expires"};
    //String[] signed_content = {"Hash", "Canonical", "Contact", "Encryption", "Policy", "Acknowledgments", "Expires", "Version", "BEGIN PGP SINGATURE"};
    
    boolean valid = false;
    if (content.contains("Contact:")) {
      valid = true;
    }
    return valid;
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
      String wellKnowUrl = String.format("%s/.well-known/security.txt", serviceMessage.toUrl());
      String rootUrl = String.format("%s/security.txt", serviceMessage.toUrl());
      LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("locating security.txt at %s", wellKnowUrl));
      HttpResponse<String> response = Unirest.get(wellKnowUrl).asString();
      if (response.getStatus() != 200) {
        LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Cannot find security txt at %s %d",wellKnowUrl, response.getStatus()));
        LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("locating security.txt at %s", rootUrl ));
        response = Unirest.get(rootUrl).asString();
        if (response.getStatus() != 200) {
          LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Cannot find security txt at %s %d",rootUrl, response.getStatus()));
        } else {
          LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Found security.txt at %s", rootUrl));
          if (contentCheck(response.getBody())) {
            LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Upserting http service field with securitytxt content : %s", response.getBody()));
            datalakeConfig.upsertHttpServiceField(serviceMessage.getDomain(), serviceMessage.getPort(), "securitytxt", response.getBody());
          } else {
            LogManager.getLogger(SecuritytxtScanApplication.class).warn(String.format("Security.txt has not passed content checker : %s", response.getBody()));
          }
          
        }
      } else {
        LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Found security.txt at %s", wellKnowUrl));
        if (contentCheck(response.getBody())) {
          LogManager.getLogger(SecuritytxtScanApplication.class).info(String.format("Upserting http service field with securitytxt content : %s", response.getBody()));
          datalakeConfig.upsertHttpServiceField(serviceMessage.getDomain(), serviceMessage.getPort(), "securitytxt", response.getBody());
        } else {
          LogManager.getLogger(SecuritytxtScanApplication.class).warn(String.format("Security.txt has not passed content checker : %s", response.getBody()));
        }
      }
            
    } catch (DatalakeStorageException ex) {
      LogManager.getLogger(SecuritytxtScanApplication.class).error(String.format("Exception with datalake : %s", ex));
      
    }
    
  }

}
