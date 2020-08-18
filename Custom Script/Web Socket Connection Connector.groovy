/*------------------------------------------------/
Script Name: Web Soclet Process Script
Creation Date: 08-10-2019
Author: Mitchell Franklin
Description: Dell Boomi does not have the ability to connect via Web Socket even using HTTP via ws://, this script allows the connection to the web socket to be processed and send through the required payload to the web socket.
Last Update Date: XX-XX-XXX
Last Update By: XXXX XXXX
Last Update Description: XXXX XXXX XXXX
/-------------------------------------------------*/

import java.util.Properties;
import java.io.InputStream;

try{

for( int i = 0; i < dataContext.getDataCount(); i++ ) {
  InputStream is = dataContext.getStream(i);
  Properties props = dataContext.getProperties(i);

  //Convert input stream (i.e. incoming document) to string
  StringBuilder logCEF = new StringBuilder();
  String content;
                                
  InputStreamReader isr = null;
  BufferedReader ibr = null;
                                
  try {
     isr = new InputStreamReader(is);
     ibr = new BufferedReader(isr);
    
     while ((content = ibr.readLine()) != null) {
        logCEF.append(content);
     }
  } catch (IOException ioe) {
     System.out.println("IO Exception occurred");
     ioe.printStackTrace();
  } finally {
     isr.close();
      ibr.close();
  }
                                
  String logcefString = logCEF.toString();


                        //Change Server and Port 
  Socket s = new Socket("Server", 8080);
  String auth_A_str = logcefString;
          
  //Write to Socket
  PrintWriter out = new PrintWriter(s.getOutputStream(), true);
  out.println(auth_A_str);
         

  s.close();

}

} catch(Exception ex) {
                                        // create the dynamic process property dpp_scriptingTryCatch
ExecutionUtil.setDynamicProcessProperty("dpp_scriptingTryCatch", ex.toString(), true);


}