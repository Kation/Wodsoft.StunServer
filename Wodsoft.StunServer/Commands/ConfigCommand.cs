using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Wodsoft.StunServer.Commands
{
    public class ConfigCommand : Command
    {
        public ConfigCommand() : base("config", "Stun server configuration.")
        {
            var statusCommand = new Command("validate", "Validate configuration.");
            statusCommand.SetHandler(ValidateAsync);
            AddCommand(statusCommand);

            var generateCommand = new Command("generate", "Generate a default configuration.");
            generateCommand.SetHandler(GenerateAsync);
            AddCommand(generateCommand);
        }

        private async Task ValidateAsync()
        {
            if (!File.Exists("config.json"))
            {
                Console.WriteLine("config.json not exists.");
                return;
            }
            Stream stream;
            try
            {
                stream = File.OpenRead("config.json");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Read configuration file failed: {ex.Message}");
                return;
            }
            var config = await JsonSerializer.DeserializeAsync<Config>(stream, SourceGenerationContext.Default.Config) ?? new Config();
            await stream.DisposeAsync();
            if (config.Validate())
            {
                Console.WriteLine("Configuration is correct.");
            }
        }

        private async Task GenerateAsync()
        {
            if (File.Exists("config.json"))
            {
                Console.Write("Detect config.json file is created. Override by a default configuration? Yes[y] or No[n]: ");
                if (Console.ReadKey().KeyChar != 'y')
                    return;
            }
            Console.WriteLine();
            Stream stream;
            try
            {
                stream = File.Create("config.json");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Create configuration file failed: {ex.Message}");
                return;
            }
            await JsonSerializer.SerializeAsync(stream, new Config(), SourceGenerationContext.Default.Config);
            await stream.FlushAsync();
            await stream.DisposeAsync();
            Console.WriteLine("Generate default configuration file successfully.");
        }
    }
}
