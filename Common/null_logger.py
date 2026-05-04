class NullLogger:
    """空日志记录器 - 用于禁用日志输出"""
    
    def log_authentication(self, *args, **kwargs):
        pass
    
    def log_message_sent(self, *args, **kwargs):
        pass
    
    def log_message_received(self, *args, **kwargs):
        pass
    
    def log_session_established(self, *args, **kwargs):
        pass
    
    def log_error(self, *args, **kwargs):
        pass
    
    def log_warning(self, *args, **kwargs):
        pass
    
    def log_message_error(self, *args, **kwargs):
        pass
    
    def log_database_operation(self, *args, **kwargs):
        pass
    
    def log_identifier_operation(self, *args, **kwargs):
        pass
    
    def log(self, *args, **kwargs):
        pass
    
    def debug(self, *args, **kwargs):
        pass
    
    def info(self, *args, **kwargs):
        pass
    
    def warn(self, *args, **kwargs):
        pass
    
    def error(self, *args, **kwargs):
        pass
    
    def critical(self, *args, **kwargs):
        pass


NULL_LOGGER = NullLogger()