package com.mycompany.app;
import java.util.Random;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        String password = "Ch@ng3m3"
        Random rand = new Random();
        System.out.println(rand.nextInt(50));
        System.out.println( "Hello World!" );
        System.out.println( "Actual password" + password );
        KeyPairGenerator keyPairGen1 = KeyPairGenerator.getInstance("RSA");
        keyPairGen1.initialize(1024); // Noncompliant
    }
}
