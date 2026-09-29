using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;

namespace Wodsoft.StunServer
{
    public class StunUdpService : StunServiceBase
    {
        private readonly StunUdpServiceOptions _options;
        private readonly ILogger _logger;

        public StunUdpService(StunUdpServiceOptions options, ILogger logger)
        {
            _options = options;
            _logger = logger;
        }

        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var thisAddressThisPortSocket = _options.PrimaryAddressPrimaryPortSocket;
                SocketAddress remoteAddress = new SocketAddress(thisAddressThisPortSocket.AddressFamily);
                var receiveBuffer = RentBuffer();
                Channel<ReceiveData> receiveChannel = Channel.CreateBounded<ReceiveData>(new BoundedChannelOptions(_options.ProcessThreads * 16)
                {
                    SingleWriter = true,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.DropWrite
                });
                var writer = receiveChannel.Writer;
                Task[] processTasks = new Task[_options.ProcessThreads];
                for (int i = 0; i < processTasks.Length; i++)
                    processTasks[i] = ProcessReceive(receiveChannel.Reader);
                ReceiveData receiveData = default;
                while (!cancellationToken.IsCancellationRequested)
                {
                    int length;
                    try
                    {
                        length = await thisAddressThisPortSocket.ReceiveFromAsync(receiveBuffer, SocketFlags.None, remoteAddress, cancellationToken).ConfigureAwait(false);
                        _logger.LogDebug($"Receive UDP request from {remoteAddress} to {thisAddressThisPortSocket.LocalEndPoint}");
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                    if (length < 20)
                        continue;
                    receiveData.Data = receiveBuffer;
                    receiveData.Length = (ushort)length;
                    if (remoteAddress.Family == AddressFamily.InterNetwork)
                        remoteAddress.Buffer.Span.Slice(2, 6).CopyTo(receiveData.SocketAddress);
                    else
                        remoteAddress.Buffer.Span.Slice(2, 18).CopyTo(receiveData.SocketAddress);
                    if (!writer.TryWrite(receiveData))
                        continue;
                    receiveBuffer = RentBuffer();
                }
                writer.Complete();
                await Task.WhenAll(processTasks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Process UDP receive error.");
            }
        }

        private async Task ProcessReceive(ChannelReader<ReceiveData> reader)
        {
            var thisAddress = _options.PrimaryAddress.GetAddressBytes();
            var thisPort = _options.PrimaryPort;
            var otherAddress = _options.SecondaryAddress.GetAddressBytes();
            var otherPort = _options.SecondaryPort;
            var thisAddressThisPortSocket = _options.PrimaryAddressPrimaryPortSocket;
            var thisAddressOtherPortSocket = _options.PrimaryAddressSecondaryPortSocket;
            var otherAddressThisPortSocket = _options.SecondaryAddressPrimaryPortSocket;
            var otherAddressOtherPortSocket = _options.SecondaryAddressSecondaryPortSocket;
            ReceiveData receiveData;
            SocketAddress remoteAddress = new SocketAddress(_options.PrimaryAddress.AddressFamily);
            while (await reader.WaitToReadAsync())
            {
                while (reader.TryRead(out receiveData))
                {
                    try
                    {
                        Memory<byte> address;
                        if (thisAddress.Length == 4)
                        {
                            receiveData.SocketAddress.Slice(0, 6).CopyTo(remoteAddress.Buffer.Span.Slice(2));
                            address = remoteAddress.Buffer.Slice(4, 4);
                        }
                        else
                        {
                            receiveData.SocketAddress.CopyTo(remoteAddress.Buffer.Span.Slice(2));
                            address = remoteAddress.Buffer.Slice(4, 16);
                        }
                        StunRequestResult result;
                        try
                        {
                            result = await HandleRequestAsync(receiveData.Data.AsMemory(0, receiveData.Length), address, receiveData.Port, thisAddress, thisPort, otherAddress, otherPort).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Handle request failed.");
                            continue;
                        }
                        finally
                        {
                            ReturnBuffer(receiveData.Data);
                        }
                        if (result.Response != null)
                        {
                            if (result.ResponsePort != default)
                                BinaryPrimitives.WriteUInt16BigEndian(remoteAddress.Buffer.Span.Slice(2), result.ResponsePort);
                            if (!result.ResponseAddress.IsEmpty)
                                result.ResponseAddress.Span.CopyTo(remoteAddress.Buffer.Span.Slice(4, result.ResponseAddress.Length));
                            var sendSocket = thisAddressThisPortSocket;
                            if (result.ChangeAddress && result.ChangePort)
                            {
                                sendSocket = otherAddressOtherPortSocket;
                            }
                            else if (result.ChangeAddress)
                            {
                                sendSocket = otherAddressThisPortSocket;
                            }
                            else if (result.ChangePort)
                            {
                                sendSocket = thisAddressOtherPortSocket;
                            }
                            try
                            {
                                _logger.LogDebug($"Send UDP response to {remoteAddress}");
                                await sendSocket.SendToAsync(result.Response, result.ResponseLength, SocketFlags.None, remoteAddress).ConfigureAwait(false);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, $"Send response to {remoteAddress} failed");
                            }
                            finally
                            {
                                ReturnBuffer(result.Response);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Process request error.");
                    }
                }
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 32)]
        private struct ReceiveData
        {
            [FieldOffset(0)]
            public byte[] Data;
            [FieldOffset(8)]
            public ushort Length;
            [FieldOffset(14)]
            private byte _address;
            public ushort Port => BinaryPrimitives.ReadUInt16BigEndian(MemoryMarshal.CreateSpan(ref _address, 2));
            public Span<byte> SocketAddress => MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref _address, 18));
        }
    }
}
