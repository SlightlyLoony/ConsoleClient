package com.dilatush.consoleclient;

import com.dilatush.util.AConfig;
import com.dilatush.util.Base64;
import com.dilatush.util.Crypto;
import com.dilatush.util.Sockets;
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
import static com.dilatush.util.Strings.isEmpty;

/**
 * Implements a command line application that connects to a console server.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public class ConsoleClient {

    private static BufferedReader reader;
    private static BufferedWriter writer;
    private static Socket socket;


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
                System.out.println( "Key: " + Base64.encode( newKey.getEncoded() ) );

                // leave...
                System.exit( 0 );
            }
            catch( NoSuchAlgorithmException _e ) {

                // if this happens, then something really weird is going on...
                System.out.println( "(Very) unexpected crypto problem: " + _e.getMessage() );
                System.exit( 1 );
            }
        }

        // we weren't doing anything else, so try to establish a connection to the requested server...
        Config config = (Config) result.getValue( "config" );
        String name = (String) result.getValue( "name" );
        Config.Server server = config.servers.get( name );

        try {
            socket = new Socket( server.socket.getAddress(), server.socket.getPort() );

            ID id = getID( socket, name );

            // get our encrypting output stream and turn it into a buffered writer...
            Key key = Crypto.getKey_AES_128( server.secret );
            CipherOutputStream cos = Crypto.getSocketOutputStream_AES_128_CTR( socket, key );
            OutputStreamWriter osw = new OutputStreamWriter( cos, StandardCharsets.UTF_8 );
            writer = new BufferedWriter( osw, 1000 );

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

            id.hashCode();
        }
        catch( IOException _e ) {
            System.out.println( _e.getMessage() );
        }
        finally {
            close( socket );
        }

        result.hashCode();
    }


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
        }
    }


    /**
     * Captures the console server's ID string, decodes it, and returns the decoded as an {@link ID} instance.  Throws an {@link IOException} on any
     * problem receiving or decoding the message.
     *
     * @param _socket The socket that's connected to the server.
     * @param _expectedName The console server name we expect to connect to.
     * @return an instance of {@link ID} containing the decoded ID string.
     * @throws IOException on any problem receiving or decoding the message.
     */
    private static ID getID( final Socket _socket, final String _expectedName ) throws IOException {

        String idString = Sockets.readLine( _socket );

        String[] parts = idString.split( "," );
        if( parts.length != 3 )
            throw new IOException( "Incorrect number of values in console server ID string: " + idString );
        if( !"Loony Console Server".equals( parts[0] ) )
            throw new IOException( "Invalid console server ID string: " + parts[0] );
        if( !_expectedName.equals( parts[2] ) )
            throw new IOException( "Console server name is not what was expected.  Was '" + parts[2] + "', expected '" + _expectedName + "'." );
        int major = 0;
        int minor = 0;
        try {
            String[] vparts = parts[1].split( "\\." );
            if( vparts.length != 2 )
                throw new IOException( "Console server version is improperly formed: " + parts[1] );
            major = Integer.parseInt( vparts[0] );
            minor = Integer.parseInt( vparts[1] );
        }
        catch( NumberFormatException _e ) {
            throw new IOException( "Console server version is improperly formed: " + parts[1] );
        }

        return new ID( parts[0], major, minor, parts[2] );
    }


    private static class ID {
        private final String server;
        private final int    major;
        private final int    minor;
        private final String name;


        public ID( final String _server, final int _major, final int _minor, final String _name ) {
            server = _server;
            major = _major;
            minor = _minor;
            name = _name;
        }
    }


    /**
     * Closes the given socket and absorbs any exception.  If the given socket is {@code null} or is already closed, this method does nothing.
     *
     * @param _socket The socket to close.
     */
    private static void close( final Socket _socket ) {
        if( (_socket != null) && !_socket.isClosed() ) {
            try {
                _socket.close();
            }
            catch( IOException _f ) {
                /* naught to do */
            }
        }
    }


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
                    byte[] key = Base64.decodeBytes( server.secret );
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


        public static class Server {

            public String name;
            public String host;
            public int port;
            public String secret;
            public String console;
            public InetSocketAddress socket;
        }
    }
}
