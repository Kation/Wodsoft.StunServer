using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Wodsoft.StunServer.Commands
{
    public class RunCommand : Command
    {
        public RunCommand() : base("run", "Run stun server.")
        {
            var verbosityOption = new Option<LogLevel>("--verbosity", "Logging verbosity.");
            verbosityOption.AddAlias("-v");
            verbosityOption.Arity = ArgumentArity.ExactlyOne;
#if DEBUG
            verbosityOption.SetDefaultValue(LogLevel.Information);
#else
            verbosityOption.SetDefaultValue(LogLevel.Warning);
#endif
            AddOption(verbosityOption);

            var serviceOption = new Option<bool>("--service", "Run as service.");
            serviceOption.AddAlias("-s");
            serviceOption.Arity = ArgumentArity.Zero;
            //serviceOption.SetDefaultValue(false);
            AddOption(serviceOption);

            this.SetHandler(RunAsync, verbosityOption, serviceOption);
        }

        private async Task RunAsync(LogLevel logLevel, bool isService)
        {
            if (isService)
                Directory.SetCurrentDirectory(Path.GetDirectoryName(Environment.ProcessPath)!);
            File.AppendAllText("log.txt", $"LogLevel: {logLevel}, IsService: {isService}\r\n");
            if (isService)
            {
                var builder = Host.CreateApplicationBuilder();
                builder.Logging.SetMinimumLevel(logLevel);
                if (OperatingSystem.IsLinux())
                {
                    builder.Services.AddSystemd();
                    builder.Logging.AddJournal();
                }
                if (OperatingSystem.IsWindows())
                {
                    builder.Services.AddWindowsService();
                    builder.Logging.AddEventLog(new Microsoft.Extensions.Logging.EventLog.EventLogSettings
                    {
                        SourceName = "StunServer"
                    });
                }
                builder.Services.AddHostedService<StunHostedService>();
                var host = builder.Build();
                await host.RunAsync();
            }
            else
            {
                var loggerFactory = LoggerFactory.Create(builder =>
                {
                    builder.SetMinimumLevel(logLevel).AddConsole();
#if DEBUG
                    builder.AddDebug();
#endif
                });
                var logger = loggerFactory.CreateLogger<StunService>();
                Config config;
                if (!File.Exists("config.json"))
                {

                    logger.LogError("Configuration file config.json not exists.");
                    Environment.ExitCode = 126;
                    return;
                }
                else
                {
                    Stream stream;
                    try
                    {
                        stream = File.OpenRead("config.json");
                    }
                    catch (Exception ex)
                    {
                        logger.LogError($"Read configuration file failed: {ex.Message}");
                        Environment.ExitCode = 126;
                        return;
                    }
                    config = await JsonSerializer.DeserializeAsync<Config>(stream, SourceGenerationContext.Default.Config) ?? new Config();
                    await stream.DisposeAsync();
                }
                if (!config.Validate())
                {
                    logger.LogError($"Configuration is not correct.");
                    Environment.ExitCode = 126;
                    return;
                }
                CancellationTokenSource cts = new CancellationTokenSource();
                Console.CancelKeyPress += (_, e) =>
                {
                    e.Cancel = true;
                    cts.Cancel();
                };
                StunService service = new StunService();
                var result = await service.RunAsync(config, logger, cts.Token).ConfigureAwait(false);
                if (!result)
                {
                    cts.Cancel();
                    Environment.ExitCode = 126;
                }
            }
        }
    }
}
