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
        Random rand = new Random();
        System.out.println(rand.nextInt(50));
        System.out.println( "Hello World!" );
    }
}
