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
            var thisAddressThisPortSocket = _options.PrimaryAddressPrimaryPortSocket;
            SocketAddress remoteAddress = new SocketAddress(thisAddressThisPortSocket.AddressFamily);
            var receiveBuffer = RentBuffer();
            Channel<ReceiveData> receiveChannel = Channel.CreateBounded<ReceiveData>(new BoundedChannelOptions(_options.ProcessThreads * 4)
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
                catch (OperationCanceledException)
                {
                    break;
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
                    if (thisAddress.Length == 4)
                        receiveData.SocketAddress.Slice(0, 6).CopyTo(remoteAddress.Buffer.Span.Slice(2));
                    else
                        receiveData.SocketAddress.CopyTo(remoteAddress.Buffer.Span.Slice(2));
                    byte[]? response;
                    bool changeAddress, changePort;
                    int responseLength;
                    ushort responsePort = receiveData.Port;
                    try
                    {
                        response = HandleRequest(receiveData.Data.AsSpan(0, receiveData.Length), thisAddress.Length == 4 ? receiveData.Address.Slice(0, 4) : receiveData.Address, ref receiveData.Port, thisAddress, thisPort, otherAddress, otherPort, out changeAddress, out changePort, out responseLength);
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
                    if (response != null)
                    {
                        if (responsePort != receiveData.Port)
                            BinaryPrimitives.WriteUInt16BigEndian(remoteAddress.Buffer.Span.Slice(2), responsePort);
                        try
                        {
                            if (!changeAddress && !changePort)
                            {
                                _logger.LogDebug($"Send UDP response from {thisAddressThisPortSocket.LocalEndPoint} to {remoteAddress}");
                                await thisAddressThisPortSocket.SendToAsync(response.AsMemory(0, responseLength), SocketFlags.None, remoteAddress).ConfigureAwait(false);
                            }
                            else if (changeAddress && !changePort)
                            {
                                _logger.LogDebug($"Send UDP response from {otherAddressThisPortSocket.LocalEndPoint} to {remoteAddress}");
                                await otherAddressThisPortSocket.SendToAsync(response.AsMemory(0, responseLength), SocketFlags.None, remoteAddress).ConfigureAwait(false);
                            }
                            else if (changeAddress && changePort)
                            {
                                _logger.LogDebug($"Send UDP response from {otherAddressOtherPortSocket.LocalEndPoint} to {remoteAddress}");
                                await otherAddressOtherPortSocket.SendToAsync(response.AsMemory(0, responseLength), SocketFlags.None, remoteAddress).ConfigureAwait(false);
                            }
                            else
                            {
                                _logger.LogDebug($"Send UDP response from {thisAddressOtherPortSocket.LocalEndPoint} to {remoteAddress}");
                                await thisAddressOtherPortSocket.SendToAsync(response.AsMemory(0, responseLength), SocketFlags.None, remoteAddress).ConfigureAwait(false);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, $"Send response to {remoteAddress} failed");
                        }
                        finally
                        {
                            ReturnBuffer(response);
                        }
                    }
                    else
                    {
                        _logger.LogDebug($"Bad request from {remoteAddress}");
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
            public ushort Port;
            [FieldOffset(16)]
            private byte _address;

            public Span<byte> Address => MemoryMarshal.CreateSpan(ref _address, 16);

            public Span<byte> SocketAddress => MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref Port, 9));
        }
    }
}
