using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.StunServer.Commands
{
    public class ServiceCommand : Command
    {
        public ServiceCommand() : base("service", "Configure stun service.")
        {
            var createCommand = new Command("create", "Create stun system service.");
            createCommand.SetHandler(Create);
            AddCommand(createCommand);

            var deleteCommand = new Command("delete", "Delete stun system service.");
            deleteCommand.SetHandler(Delete);
            AddCommand(deleteCommand);
        }

        private void Create()
        {
            var service = ServiceSelf.Service.Create("stunservice");            
            try
            {
                service.CreateStart(Environment.ProcessPath!, new ServiceSelf.ServiceOptions
                {
                    Arguments =
                    [
                        new ServiceSelf.Argument("run"),
                        new ServiceSelf.Argument("-s")
                    ],
                    Description = "Stun server service"
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Create service failed: {ex.Message}");
            }
        }

        private void Delete()
        {
            var service = ServiceSelf.Service.Create("stunservice");
            try
            {
                service.StopDelete();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Delete service failed: {ex.Message}");
            }
        }
    }
}
