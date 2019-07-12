import ghidra.app.util.headless.HeadlessScript;

import java.net.URL;
import java.net.URLClassLoader;


public class Test extends HeadlessScript {

    @Override
    public void run() throws Exception {
	
    	ClassLoader cl = ClassLoader.getSystemClassLoader();

        URL[] urls = ((URLClassLoader)cl).getURLs();

        for(URL url: urls){
        	System.out.println(url.getFile());
		}
                                         
    }
}
