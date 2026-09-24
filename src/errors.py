class ParseError(Exception): 
    '''
    Lỗi chung cho các packet
    '''

class MalformedPacketError(ParseError):
    '''
    Lỗi packet bị thiếu header, bị truncated hoặc cấu trúc sai 
    '''
