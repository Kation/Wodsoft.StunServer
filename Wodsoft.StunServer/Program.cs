using System;
using System.Buffers;
using System.CommandLine;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using System.Threading;
using Wodsoft.StunServer;
using Wodsoft.StunServer.Commands;


var rootCommand = new RootCommand
{
    new ConfigCommand(),
    new RunCommand()
};
await rootCommand.InvokeAsync(args);