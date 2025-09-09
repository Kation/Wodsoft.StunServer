using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Wodsoft.StunServer
{
    public class StunHostedService : IHostedService
    {
        private readonly ILogger<StunService> _logger;
        private readonly StunService _service;
        private CancellationTokenSource? _cts;

        public StunHostedService(ILogger<StunService> logger)
        {
            _logger = logger;
            _service = new StunService();
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            Config config;
            if (!File.Exists("config.json"))
            {
                throw new InvalidOperationException("Configuration file config.json not exists.");
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
                    throw new InvalidOperationException("Read configuration file failed.", ex);
                }
                config = await JsonSerializer.DeserializeAsync<Config>(stream, SourceGenerationContext.Default.Config) ?? new Config();
                await stream.DisposeAsync();
            }
            if (!config.Validate())
                throw new InvalidOperationException("Configuration is not correct.");
            _cts = new CancellationTokenSource();
            if (!_service.Start(config, _logger, _cts.Token))
            {
                _cts.Cancel();
                throw new InvalidOperationException("Start stun service failed.");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _cts!.Cancel();
            return _service.StopAsync();
        }
    }
}
