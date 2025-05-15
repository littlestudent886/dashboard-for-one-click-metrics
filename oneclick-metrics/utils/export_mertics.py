import signal
from prometheus_client import start_http_server, Gauge
import logging

class MetricsExporter:
    def __init__(self):
        self.server = None
    
    def start_server(self, port: int):
        """
        start a http server to expose metrics
        :param port: port to expose metrics
        """  
        self.server = start_http_server(port)
        logging.info(f"Successfully started metrics exporter HTTP server on port {port}")
    
    def register_gauge(self, metric_name, metric_description, label_names):
        """
        register a gauge metric
        :param metric_name: name of the metric
        :param metric_description: description of the metric
        :param label_names: list of label names
        """
        return Gauge(metric_name, metric_description, label_names)