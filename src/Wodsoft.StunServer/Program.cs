using System;
using System.Buffers;
using System.Buffers.Binary;
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

var endPoint = new IPEndPoint(IPAddress.Parse("192.168.0.1"), 5000);
var address = endPoint.Serialize();
var port = BinaryPrimitives.ReadUInt16BigEndian(address.Buffer.Span.Slice(2));
var rootCommand = new RootCommand
{
    new ConfigCommand(),
    new RunCommand(),
    new ServiceCommand()
};
return await rootCommand.Parse(args).InvokeAsync();