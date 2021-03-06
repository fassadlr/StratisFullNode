﻿using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using NBitcoin;
using NLog;
using Stratis.Bitcoin.Features.Interop.ETHClient;
using Stratis.Bitcoin.Features.Interop.Models;
using Stratis.Bitcoin.Features.Wallet;
using Stratis.Bitcoin.Utilities.JsonErrors;
using Stratis.Features.FederatedPeg.Conversion;

namespace Stratis.Bitcoin.Features.Interop.Controllers
{
    [ApiVersion("1")]
    [Route("api/[controller]")]
    public class InteropController : Controller
    {
        private readonly Network network;

        private readonly IConversionRequestRepository conversionRequestRepository;

        private readonly IInteropTransactionManager interopTransactionManager;

        private readonly IETHCompatibleClientProvider ethCompatibleClientProvider;

        private readonly InteropSettings interopSettings;

        private readonly ILogger logger;

        public InteropController(Network network,
            IConversionRequestRepository conversionRequestRepository,
            IInteropTransactionManager interopTransactionManager,
            IETHCompatibleClientProvider ethCompatibleClientProvider,
            InteropSettings interopSettings)
        {
            this.network = network;
            this.conversionRequestRepository = conversionRequestRepository;
            this.interopTransactionManager = interopTransactionManager;
            this.ethCompatibleClientProvider = ethCompatibleClientProvider;
            this.interopSettings = interopSettings;
            this.logger = LogManager.GetCurrentClassLogger();
        }

        [Route("status")]
        [HttpGet]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public IActionResult InteropStatus()
        {
            try
            {
                var response = new InteropStatusResponseModel();

                var mintRequests = new List<ConversionRequestModel>();

                foreach (ConversionRequest request in this.conversionRequestRepository.GetAllMint(false))
                {
                    mintRequests.Add(new ConversionRequestModel()
                    {
                        RequestId = request.RequestId,
                        RequestType = request.RequestType,
                        RequestStatus = request.RequestStatus,
                        BlockHeight = request.BlockHeight,
                        DestinationAddress = request.DestinationAddress,
                        DestinationChain = request.DestinationChain.ToString(),
                        Amount = request.Amount,
                        Processed = request.Processed
                    });
                }

                response.MintRequests = mintRequests;

                var burnRequests = new List<ConversionRequestModel>();

                foreach (ConversionRequest request in this.conversionRequestRepository.GetAllBurn(false))
                {
                    burnRequests.Add(new ConversionRequestModel()
                    {
                        RequestId = request.RequestId,
                        RequestType = request.RequestType,
                        RequestStatus = request.RequestStatus,
                        BlockHeight = request.BlockHeight,
                        DestinationAddress = request.DestinationAddress,
                        DestinationChain = request.DestinationChain.ToString(),
                        Amount = request.Amount,
                        Processed = request.Processed
                    });
                }

                response.MintRequests = burnRequests;

                var receivedVotes = new Dictionary<string, List<string>>();

                foreach ((string requestId, HashSet<PubKey> pubKeys) in this.interopTransactionManager.GetStatus())
                {
                    var pubKeyList = new List<string>();

                    foreach (PubKey pubKey in pubKeys)
                    {
                        pubKeyList.Add(pubKey.ToHex());
                    }

                    receivedVotes.Add(requestId, pubKeyList);
                }

                response.ReceivedVotes = receivedVotes;

                return this.Json(response);
            }
            catch (Exception e)
            {
                this.logger.Error("Exception occurred: {0}", e.ToString());
                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Retrieves the list of current owners for the multisig wallet contract.
        /// </summary>
        /// <param name="destinationChain">The chain the multisig wallet contract is deployed to.</param>
        /// <returns>The list of owner accounts for the multisig wallet contract.</returns>
        [Route("owners")]
        [HttpGet]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public IActionResult Owners(DestinationChain destinationChain)
        {
            try
            {
                if (!this.ethCompatibleClientProvider.IsChainSupportedAndEnabled(destinationChain))
                    return this.Json($"{destinationChain} not enabled or supported!");

                IETHClient client = this.ethCompatibleClientProvider.GetClientForChain(destinationChain);

                return this.Json(client.GetOwnersAsync().GetAwaiter().GetResult());
            }
            catch (Exception e)
            {
                this.logger.Error("Exception occurred: {0}", e.ToString());

                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Creates and broadcasts an 'addOwner()' contract call on the multisig wallet contract.
        /// This can only be done by one of the current owners of the contract, and needs to be confirmed by a sufficient number of the other owners.
        /// </summary>
        /// <param name="destinationChain">The chain the multisig wallet contract is deployed to.</param>
        /// <param name="newOwnerAddress">The account of the new owner to be added.</param>
        /// <param name="gasPrice">The gas price to use for transaction submission.</param>
        /// <returns>The transactionId of the multisig wallet contract transaction, which is then used to confirm the transaction.</returns>
        [Route("addowner")]
        [HttpGet]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public IActionResult AddOwner(DestinationChain destinationChain, string newOwnerAddress, int gasPrice)
        {
            try
            {
                if (!this.ethCompatibleClientProvider.IsChainSupportedAndEnabled(destinationChain))
                    return this.Json($"{destinationChain} not enabled or supported!");

                IETHClient client = this.ethCompatibleClientProvider.GetClientForChain(destinationChain);
                string data = client.EncodeAddOwnerParams(newOwnerAddress);

                ETHInteropSettings settings = this.interopSettings.GetSettingsByChain(destinationChain);

                // TODO: Maybe for convenience the gas price could come from the external API poller
                return this.Json(client.SubmitTransactionAsync(settings.MultisigWalletAddress, 0, data).GetAwaiter().GetResult());
            }
            catch (Exception e)
            {
                this.logger.Error("Exception occurred: {0}", e.ToString());

                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Creates and broadcasts a 'removeOwner()' contract call on the multisig wallet contract.
        /// This can only be done by one of the current owners of the contract, and needs to be confirmed by a sufficient number of the other owners.
        /// </summary>
        /// <param name="destinationChain">The chain the multisig wallet contract is deployed to.</param>
        /// <param name="existingOwnerAddress">The account of the owner to be removed.</param>
        /// <param name="gasPrice">The gas price to use for transaction submission.</param>
        /// <returns>The transactionId of the multisig wallet contract transaction, which is then used to confirm the transaction.</returns>
        [Route("removeowner")]
        [HttpGet]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public IActionResult RemoveOwner(DestinationChain destinationChain, string existingOwnerAddress, int gasPrice)
        {
            try
            {
                if (!this.ethCompatibleClientProvider.IsChainSupportedAndEnabled(destinationChain))
                    return this.Json($"{destinationChain} not enabled or supported!");

                IETHClient client = this.ethCompatibleClientProvider.GetClientForChain(destinationChain);
                string data = client.EncodeRemoveOwnerParams(existingOwnerAddress);

                ETHInteropSettings settings = this.interopSettings.GetSettingsByChain(destinationChain);

                // TODO: Maybe for convenience the gas price could come from the external API poller
                return this.Json(client.SubmitTransactionAsync(settings.MultisigWalletAddress, 0, data).GetAwaiter().GetResult());
            }
            catch (Exception e)
            {
                this.logger.Error("Exception occurred: {0}", e.ToString());

                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Explicitly confirms a given multisig wallet contract transactionId by submitting a contract call transaction to the network.
        /// <remarks>This can only be called once per multisig owner. Additional calls by the same owner account will simply fail and waste gas.</remarks>
        /// </summary>
        /// <param name="destinationChain">The chain the multisig wallet contract is deployed to.</param>
        /// <param name="transactionId">The multisig wallet transactionId (this is an integer, not an on-chain transaction hash).</param>
        /// <param name="gasPrice">The gas price to use for submitting the confirmation.</param>
        /// <returns>The on-chain transaction hash of the contract call transaction.</returns>
        [Route("confirmtransaction")]
        [HttpGet]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public IActionResult ConfirmTransaction(DestinationChain destinationChain, int transactionId, int gasPrice)
        {
            try
            {
                if (!this.ethCompatibleClientProvider.IsChainSupportedAndEnabled(destinationChain))
                    return this.Json($"{destinationChain} not enabled or supported!");

                IETHClient client = this.ethCompatibleClientProvider.GetClientForChain(destinationChain);

                return this.Json(client.ConfirmTransactionAsync(transactionId).GetAwaiter().GetResult());
            }
            catch (Exception e)
            {
                this.logger.Error("Exception occurred: {0}", e.ToString());

                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }

        /// <summary>
        /// Creates and broadcasts a 'changeRequirement()' contract call on the multisig wallet contract.
        /// This can only be done by one of the current owners of the contract, and needs to be confirmed by a sufficient number of the other owners.
        /// <remarks>This should only be done once all owner modifications are complete to save gas and orchestrating confirmations.</remarks>
        /// </summary>
        /// <param name="destinationChain">The chain the multisig wallet contract is deployed to.</param>
        /// <param name="requirement">The new threshold for confirmations on the multisig wallet contract. Can usually be numOwners / 2 rounded up.</param>
        /// <param name="gasPrice">The gas price to use for submitting the contract call transaction.</param>
        /// <returns></returns>
        [Route("changerequirement")]
        [HttpGet]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public IActionResult ChangeRequirement(DestinationChain destinationChain, int requirement, int gasPrice)
        {
            try
            {
                if (!this.ethCompatibleClientProvider.IsChainSupportedAndEnabled(destinationChain))
                    return this.Json($"{destinationChain} not enabled or supported!");

                IETHClient client = this.ethCompatibleClientProvider.GetClientForChain(destinationChain);

                string data = client.EncodeChangeRequirementParams(requirement);

                ETHInteropSettings settings = this.interopSettings.GetSettingsByChain(destinationChain);

                // TODO: Maybe for convenience the gas price could come from the external API poller
                return this.Json(client.SubmitTransactionAsync(settings.MultisigWalletAddress, 0, data).GetAwaiter().GetResult());
            }
            catch (Exception e)
            {
                this.logger.Error("Exception occurred: {0}", e.ToString());

                return ErrorHelpers.BuildErrorResponse(HttpStatusCode.BadRequest, e.Message, e.ToString());
            }
        }
    }
}
