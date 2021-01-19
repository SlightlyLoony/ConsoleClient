package com.dilatush.consoleclient;

import com.dilatush.util.cli.CommandLine;
import com.dilatush.util.cli.InteractiveMode;
import com.dilatush.util.cli.ParameterMode;
import com.dilatush.util.cli.ParsedCommandLine;
import com.dilatush.util.cli.argdefs.ArgDef;
import com.dilatush.util.cli.argdefs.OptArgDef;
import com.dilatush.util.cli.argdefs.OptArgNames;
import com.dilatush.util.cli.argdefs.PosArgDef;
import com.dilatush.util.cli.parsers.AConfigParser;

/**
 * Static container class for method to define and parse the command line for the ConsoleClient app.
 *
 * @author Tom Dilatush  tom@dilatush.com
 */
public class CmdLine {

    public static ParsedCommandLine get( final String[] _args ) {

        CommandLine commandLine = init();
        return commandLine.parseAndHandle( _args );
    }


    private static CommandLine init() {

        CommandLine commandLine = get();

        commandLine.add( summaryDef()  );
        commandLine.add( detailDef()   );
        commandLine.add( configDef()   );
        commandLine.add( nameDef()     );
        commandLine.add( keygenDef()   );
        commandLine.setHelpReferenceNames( "summary", "detail" );

        return commandLine;
    }


    private static CommandLine get() {

        return new CommandLine(
                "console",
                "Connects to a console server.",
                "Connects to a console server over the network on an encrypted connection.",
                80,  // help width
                4    // help indent
        );
    }


    private static ArgDef keygenDef() {
        return OptArgDef.getSingleBinaryOptArgDef(
                "keygen",
                "Generate key for new console server installation.",
                "Generate key for new console server installation.",
                new OptArgNames( "k;key" )
        );
    }


    private static ArgDef summaryDef() {

        return OptArgDef.getSingleBinaryOptArgDef(
                "summary",
                "Display summary help.",
                "Display summary help.",
                new OptArgNames( "?;?" )
        );
    }


    private static ArgDef detailDef() {

        return OptArgDef.getSingleBinaryOptArgDef(
                "detail",
                "Display detailed help.",
                "Display detailed help.",
                new OptArgNames( "h;help" )
        );
    }


    private static ArgDef nameDef() {

        return new PosArgDef(
                "name",
                "The name of the console server to connect to.",
                "The name of the console server (in the configuration file) to connect to.  The named configuration file entry includes the " +
                        "network address, shared secret, and the console name for each console server.",
                1,
                "consoleName",
                String.class,
                ParameterMode.OPTIONAL,
                "test",
                null,
                null
        );
    }


    private static ArgDef configDef() {

        return new OptArgDef(
                "config",
                "Path to configuration file.",
                "Path to configuration file.",
                1,
                "configFile",
                ConsoleClient.Config.class,
                ParameterMode.MANDATORY,
                null,
                new AConfigParser( ConsoleClient.Config.class ),
                null,
                new OptArgNames( "c;config" ),
                System.getProperty( "user.home" ) + "/.console/config.js",
                InteractiveMode.DISALLOWED,
                null
        );
    }
}
