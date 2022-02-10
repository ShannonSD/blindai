import os
import logging
import ssl
from enum import IntEnum
from cbor2 import dumps, loads
from grpc import ssl_channel_credentials, secure_channel, RpcError
from utils.utils import *
from securedexchange_pb2 import SimpleReply, ModelResult, Model, Data
from securedexchange_pb2_grpc import ExchangeStub
from untrusted_pb2_grpc import AttestationStub
from untrusted_pb2 import (
    GetCertificateRequest as certificate_request,
    GetSgxQuoteWithCollateralRequest as quote_request
)
from dcap_attestation import (
    verify_claims,
    verify_dcap_attestation,
    get_server_cert,
    load_policy,
)

PORTS = {"untrusted_enclave": "50052", "attested_enclave": "50051"}

class BlindAiClient:

    class ModelDatumType(IntEnum):
        F32 = 0
        F64 = 1
        I32 = 2
        I64 = 3
        U32 = 4
        U64 = 5
    
    def __init__(self, debug_mode=False):

        self.channel = None
        self.policy = None
        self.stub = None

        if debug_mode == True:
            os.environ["GRPC_TRACE"] = "transport_security,tsi"
            os.environ["GRPC_VERBOSITY"] = "DEBUG"
        self.SIMULATION_MODE = False

    def _is_connected(self):
        return self.channel is not None

    def _close_channel(self):
        if self._is_connected():
            self.channel.close()

    def connect_server(
        self,
        addr: str,
        server_name="blindai-srv",
        policy=None,
        certificate=None,
        simulation=False,
        no_untrusted_cert_check=False,
    ):

        self.DISABLE_UNTRUSTED_SERVER_CERT_CHECK = no_untrusted_cert_check
        self.SIMULATION_MODE = simulation
        if self.SIMULATION_MODE is True: 
            self.DISABLE_UNTRUSTED_SERVER_CERT_CHECK = True

        addr = strip_https(addr)

        untrusted_client_to_enclave = addr + ":" + PORTS["untrusted_enclave"]
        attested_client_to_enclave = addr + ":" + PORTS["attested_enclave"]

        if self.DISABLE_UNTRUSTED_SERVER_CERT_CHECK:
            logging.warning("Untrusted server certificate check bypassed")
            try:
                untrusted_server_cert = ssl.get_server_certificate([addr, PORTS["untrusted_enclave"]])
                untrusted_server_creds = grpc.ssl_channel_credentials(root_certificates=bytes(untrusted_server_cert, encoding="utf8"))
            except:
                logging.error("Enable to connect to server")
                return False
        else:
            try:
                with open(certificate, "rb") as f:
                    untrusted_server_creds = ssl_channel_credentials(
                        root_certificates=f.read()
                    )
            except:
                logging.error("Certificate not found or not valid")
                return False


        connection_options = (("grpc.ssl_target_name_override", server_name),)

        try:
            channel = secure_channel(
                untrusted_client_to_enclave,
                untrusted_server_creds,
                options=connection_options,
            )
            stub = AttestationStub(channel)
            if self.SIMULATION_MODE:
                logging.warning("Attestation process is bypassed : running without requesting and checking attestation")
                response = stub.GetCertificate(certificate_request())
                server_cert = encode_certificate(response.enclave_tls_certificate)
            
            else:
                self.policy = load_policy(policy)
                if self.policy is None:
                    logging.error("Policy not found or not valid")
                    return False
                    
                response = stub.GetSgxQuoteWithCollateral(quote_request())                    
                claims = verify_dcap_attestation(
                    response.quote, 
                    response.collateral, 
                    response.enclave_held_data
                )

                verify_claims(claims, self.policy)
                server_cert = get_server_cert(claims)

                logging.info(f"Quote verification passed")
                logging.info(f"Certificate from attestation process\n {server_cert.decode('ascii')}")
                logging.info(f"MREnclave\n" + claims["sgx-mrenclave"])

            channel.close()

            server_creds = ssl_channel_credentials(root_certificates=server_cert)
            channel = secure_channel(
                attested_client_to_enclave, server_creds, options=connection_options
            )

            self.stub = ExchangeStub(channel)
            self.channel = channel
            logging.info("Successfuly connected to the server")

        except RpcError as rpc_error:
            check_rpc_exception(rpc_error)

        return True

    def upload_model(self, model=None, shape=None, datum=ModelDatumType.F32):
        """Upload an inference model to the server"""

        if datum is None:
            datum = self.ModelDatumType.F32
        response = SimpleReply()
        response.ok = False
        if not self._is_connected():
            response.msg = "Not connected to server"
            return response
        try:
            with open(model, "rb") as f:
                data = f.read()
            input_fact = list(shape)
            response = self.stub.SendModel(
                iter(
                    [
                        Model(length=len(data), input_fact=input_fact, data=chunk, datum=int(datum))
                        for chunk in create_byte_chunk(data)
                    ]
                )
            )
        except RpcError as rpc_error:
            check_rpc_exception(rpc_error)
            response.msg = "GRPC error"
        except FileNotFoundError:
            response.msg = "Model not found"

        return response

    def run_model(self, data_list):
        """Send data to the server to make a secure inference"""
        response = ModelResult()
        response.ok = False
        if not self._is_connected():
            response.msg = "Not connected to server"
            return response
        try:
            serialized_bytes = dumps(data_list)
            response = self.stub.RunModel(
                iter(
                    [
                        Data(input=serialized_bytes_chunk)
                        for serialized_bytes_chunk in create_byte_chunk(serialized_bytes)
                    ]
                )
            )
            return response
        except RpcError as rpc_error:
            check_rpc_exception(rpc_error)
            response.msg = "GRPC error"
            
        return response

    def close_connection(self):
        if self._is_connected():
            self._close_channel()
            self.channel = None
            self.stub = None
            self.policy = None
