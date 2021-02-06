package com.dilatush.consoleclient;

import com.dilatush.util.*;
import com.dilatush.util.cli.ParsedCommandLine;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import static com.dilatush.util.General.isNull;
import static com.dilatush.util.Sockets.close;
import static com.dilatush.util.Strings.isEmpty;

/**
 * Implements a command line application that connects to a console server.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public class ConsoleClient {

    // the highest major.minor version of the protocol that this application is compatible with...
    private static final int MAJOR_VERSION = 1;
    private static final int MINOR_VERSION = 0;

    private static BufferedReader reader;
    private static Socket socket;


    /**
     * The entry point of this program.
     *
     * @param _args The command line arguments.
     */
    public static void main( final String[] _args ) {

        // get our parsed command line - valid and no help...
        ParsedCommandLine result = CmdLine.get( _args );

        // see if the user wants a key generated...
        if( result.isPresent( "keygen" ) ) {

            try {
                // generate a key...
                KeyGenerator keygen = KeyGenerator.getInstance( "AES" );
                keygen.init( 128, Crypto.getSecureRandom() );
                SecretKey newKey = keygen.generateKey();

                // print it out in base 64 form...
                System.out.println( "Key: " + Base64Fast.encode( newKey.getEncoded() ) );

                // leave...
                System.exit( 0 );
            }
            catch( NoSuchAlgorithmException _e ) {

                // if this happens, then something really weird is going on...
                System.out.println( "(Very) unexpected crypto problem: " + _e.getMessage() );
                System.exit( 1 );
            }
        }

        // if we have no config, complain...
        if( result.getValue( "config" ) == null ) {
            System.out.println( "No configuration at <user>/.console/config.js, and none specified.");
            return;
        }

        // get our configuration...
        Config config = (Config) result.getValue( "config" );

        // if we didn't get a name, list what we've configured...
        if( !result.get( "name" ).present ) {

            System.out.println( "No connection specified" );
            showServers( config );
            return;
        }

        // we weren't doing anything else, so try to establish a connection to the requested server...
        String name = (String) result.getValue( "name" );
        Config.Server server = config.servers.get( name );
        if( server == null ) {
            System.out.println( "Server is not configured: " + name );
            showServers( config );
            return;
        }

        try {
            socket = new Socket( server.socket.getAddress(), server.socket.getPort() );

            // get the server ID and make sure all is ok...
            ID id = getID( socket );
            if( !server.serverName.equals( id.name ) )
                throw new IOException( "Invalid server name: got '" + id.name + "', expected '" + server.serverName + "'" );
            if( (id.major > MAJOR_VERSION) || (id.minor > MINOR_VERSION) )
                throw new IOException( "Incompatible version: " + id.major + "." + id.minor );

            // get our encrypting output stream and turn it into a buffered writer...
            Key key = Crypto.getKey_AES_128( server.secret );
            CipherOutputStream cos = Crypto.getSocketOutputStream_AES_128_CTR( socket, key );
            OutputStreamWriter osw = new OutputStreamWriter( cos, StandardCharsets.UTF_8 );
            BufferedWriter writer = new BufferedWriter( osw, 1000 );

            // send the console name to the server...
            writer.write( server.console + "\n" );
            writer.flush();

            // get our decrypting input stream and turn it into a buffered reader...
            CipherInputStream cis = Crypto.getSocketInputStream_AES_128_CTR( socket, key );
            InputStreamReader isr = new InputStreamReader( cis, StandardCharsets.UTF_8 );
            reader = new BufferedReader( isr, 1000 );

            // get the console server's response
            String serverResponse = reader.readLine();
            if( !"OK".equals( serverResponse ) )
                throw new IOException( "Invalid server response received: " + serverResponse );

            // if we make it to here, we've got a bidirectional encrypted connection set up with our buffered reader and writer...

            // start up our input reader thread...
            Thread reader = new Thread( new InputReader() );
            reader.setDaemon( true );
            reader.start();

            // loop while getting user input...
            BufferedReader keyReader = new BufferedReader( new InputStreamReader( System.in ) );
            while( !Thread.currentThread().isInterrupted() ) {
                String line = keyReader.readLine();
                if( isNull( line ) )
                    break;
                writer.write( line );
                writer.newLine();
                writer.flush();
            }

            System.out.println( "Our work is done here..." );

        }
        catch( IOException _e  ) {
            System.out.println( _e.getMessage() );
        }
        finally {
            close( socket );
        }
    }


    /**
     * Show a list of the configured servers.
     *
     * @param _config The configuration object.
     */
    private static void showServers( final Config _config ) {
        System.out.println( "Configured server connections available:");
        _config.servers.forEach(
                (name,server) -> System.out.println( "  " + name + ":  " + server.host + ":" + server.port + " --> " + server.console )
        );
    }


    /**
     * A simple socket reader that reads from the decrypting input reader.
     */
    private static class InputReader implements Runnable {

        /**
         * When an object implementing interface <code>Runnable</code> is used to create a thread, starting the thread causes the object's
         * <code>run</code> method to be called in that separately executing
         * thread.
         * <p>
         * The general contract of the method <code>run</code> is that it may take any action whatsoever.
         *
         * @see Thread#run()
         */
        @Override
        public void run() {

            while( !Thread.currentThread().isInterrupted() ) {
                try {
                    String line = reader.readLine();
                    if( isNull( line ) )
                        break;
                    System.out.println( line );
                }
                catch( IOException _e ) {
                    System.out.println( "Error while reading from console server: " + _e.getMessage() );
                    close( socket );
                }
            }
            try {
                System.in.close();
            }
            catch( IOException _e ) {
                _e.printStackTrace();
            }
        }
    }


    /**
     * Captures the console server's ID string, decodes it, and returns the decoded as an {@link ID} instance.  Throws an {@link IOException} on any
     * problem receiving or decoding the message.
     *
     * @param _socket The socket that's connected to the server.
     * @return an instance of {@link ID} containing the decoded ID string.
     * @throws IOException on any problem receiving or decoding the message.
     */
    private static ID getID( final Socket _socket ) throws IOException {

        String idString = Sockets.readLine( _socket );

        String[] parts = idString.split( "," );
        if( parts.length != 3 )
            throw new IOException( "Incorrect number of values in console server ID string: " + idString );
        if( !"Loony Console Server".equals( parts[0] ) )
            throw new IOException( "Invalid console server ID string: " + parts[0] );
        int major;
        int minor;
        try {
            String[] versionParts = parts[1].split( "\\." );
            if( versionParts.length != 2 )
                throw new IOException( "Console server version is improperly formed: " + parts[1] );
            major = Integer.parseInt( versionParts[0] );
            minor = Integer.parseInt( versionParts[1] );
        }
        catch( NumberFormatException _e ) {
            throw new IOException( "Console server version is improperly formed: " + parts[1] );
        }

        return new ID( major, minor, parts[2] );
    }


    /**
     * Simple POJO to hold the results of {@link #getID(Socket)}.
     */
    private static class ID {
        private final int    major;
        private final int    minor;
        private final String name;


        public ID( final int _major, final int _minor, final String _name ) {
            major = _major;
            minor = _minor;
            name = _name;
        }
    }


    /**
     * Configuration class for this application.
     */
    public static class Config extends AConfig {

        public Map<String,Server> servers;

        @Override
        public void verify( final List<String> _list ) {

            validate( () -> servers != null, _list, "Servers map not initialized" );

            // iterate over all our servers to validate (and set the socket address)...
            for( Server server : servers.values() ) {

                validate( () -> !isEmpty( server.name), _list, "Missing server name" );
                validate( () -> !isEmpty( server.host ), _list, "Missing host name or address for " + server.name );
                validate( () -> (server.port >= 1024) && (server.port <= 65535), _list, "Port not in range [1024..65535] for " + server.name );
                validate( () -> !isEmpty( server.secret ), _list, "Missing secret key for " + server.name );
                if( !isEmpty( server.secret )) {
                    byte[] key = Base64Fast.decodeBytes( server.secret );
                    validate( () -> key.length == 16, _list, "Invalid secret key length for " + server.name );
                }
                validate( () -> !isEmpty( server.console ), _list, "Missing console name for " + server.name );
                try {
                    server.socket = new InetSocketAddress( server.host, server.port );
                }
                catch( Exception _e ) {
                    validate( () -> false, _list, "Cannot create socket for " + server.name + ": " + _e.getMessage() );
                }
            }
        }


        /**
         * Configuration of a server.
         */
        public static class Server {

            public String name;               // the name used to select this configuration on the console client's command line
            public String serverName;         // the name of the console server (as configured on the server)
            public String host;               // the host name or IP address of the console server
            public int port;                  // the TCP port that the console server is listening on
            public String secret;             // the shared secret (AES 128 bit key, base64 encoded)
            public String console;            // the name of the console provider to connect to (as configured on the console server)
            public InetSocketAddress socket;  // the socket to connect to; created from host and port by configuration validation
        }
    }
}
