﻿using Microsoft.Extensions.Logging;
using Stratis.SmartContracts.Core;
using Stratis.SmartContracts.Core.State;

namespace Stratis.SmartContracts.Executor.Reflection
{
    public sealed class CallSmartContract : ISmartContractExecutor
    {
        private readonly ILogger logger;
        private readonly IContractStateRepository stateSnapshot;
        private readonly ILoggerFactory loggerFactory;
        private readonly ISmartContractResultRefundProcessor refundProcessor;
        private readonly ISmartContractResultTransferProcessor transferProcessor;
        private readonly ISmartContractVirtualMachine vm;
        private readonly ICallDataSerializer serializer;

        public CallSmartContract(ILoggerFactory loggerFactory,
            ICallDataSerializer serializer,
            IContractStateRepository stateSnapshot,
            ISmartContractResultRefundProcessor refundProcessor,
            ISmartContractResultTransferProcessor transferProcessor,
            ISmartContractVirtualMachine vm)
        {
            this.logger = loggerFactory.CreateLogger(this.GetType());
            this.loggerFactory = loggerFactory;
            this.stateSnapshot = stateSnapshot;
            this.refundProcessor = refundProcessor;
            this.transferProcessor = transferProcessor;
            this.vm = vm;
            this.serializer = serializer;
        }

        public ISmartContractExecutionResult Execute(ISmartContractTransactionContext transactionContext)
        {
            this.logger.LogTrace("()");

            var callDataDeserializationResult = this.serializer.Deserialize(transactionContext.ScriptPubKey.ToBytes());

            // TODO Handle deserialization failure

            var callData = callDataDeserializationResult.Value;

            var gasMeter = new GasMeter(callData.GasLimit);

            var context = new TransactionContext(
                transactionContext.TransactionHash,
                transactionContext.BlockHeight,
                transactionContext.CoinbaseAddress,
                transactionContext.Sender,
                transactionContext.TxOutValue);           

            this.logger.LogTrace("()");

            var result = this.vm.ExecuteMethod(gasMeter,
                this.stateSnapshot, 
                callData,
                context);

            var revert = result.ExecutionException != null;

            this.logger.LogTrace("(-)");

            var internalTransaction = this.transferProcessor.Process(this.stateSnapshot,
                callData,
                transactionContext,
                result.InternalTransfers,
                revert);

            (var fee, var refundTxOuts) = this.refundProcessor.Process(
                callData,
                transactionContext.MempoolFee,
                transactionContext.Sender,
                result.GasConsumed,
                result.ExecutionException);

            var executionResult = new SmartContractExecutionResult
            {
                Exception = result.ExecutionException,
                GasConsumed = result.GasConsumed,
                Return = result.Result,
                InternalTransaction = internalTransaction,
                Fee = fee,
                Refunds = refundTxOuts
            };

            if (revert)
            {
                this.stateSnapshot.Rollback();
            }
            else
            {
                this.stateSnapshot.Commit();
            }

            return executionResult;
        }
    }
}