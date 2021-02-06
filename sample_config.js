/*
 * The init( config ) function that will be called by AConfig.init().
 */
function init( config ) {

    var Map               = Java.type( "java.util.HashMap" );
    var Server            = Java.type( "com.dilatush.consoleclient.ConsoleClient.Config.Server" );

    // create our map...
    config.servers = new Map();

    var server;

    // create the named console server/provider configurations...
    // repeat the block of code below for each named configuration...

    server = new Server();
    server.name       = "test";                   // the name used to select this configuration on the console client's command line
    server.serverName = "test"                    // the name of the console server (as configured on the server)
    server.host       = "127.0.0.1";              // the host name or IP address of the console server
    server.port       = 8217;                     // the TCP port that the console server is listening on
    server.secret     = "abcdefghijklmnopqrstuA"; // the shared secret (AES 128 bit key, base64 encoded)
    server.console    = "test";                   // the name of the console provider to connect to (as configured on the console server)
    config.servers.put( server.name, server );
}
