class ParseError(Exception): 
    '''
    Lỗi chung cho các packet
    '''

class MalformedPacketError(ParseError):
    '''
    Lỗi packet bị thiếu header, bị truncated hoặc cấu trúc sai 
    '''
class UnsupportedProtocolError(ParseError):
    """Protocol không nằm trong danh sách hỗ trợ."""


class DecodeError(ParseError):
    """Payload không decode được."""