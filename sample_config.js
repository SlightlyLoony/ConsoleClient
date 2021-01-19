/*
 * The init( config ) function that will be called by AConfig.init().
 */
function init( config ) {

    var Map               = Java.type( "java.util.HashMap" );
    var Server            = Java.type( "com.dilatush.consoleclient.ConsoleClient.Config.Server" );

    // create our map...
    config.servers = new Map();

    // create our entries...

    var server = new Server();
    server.name = "test";
    server.host = "127.0.0.1";
    server.port = 8217;
    server.secret = "abcdefghijklmnopqrstuA";
    server.console = "echo";
    config.servers.put( server.name, server );
}