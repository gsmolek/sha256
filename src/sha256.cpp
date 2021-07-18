#include "sha256.h"
/*
unsigned int gsm::Sha256::h0;
unsigned int gsm::Sha256::h1;
unsigned int gsm::Sha256::h2;
unsigned int gsm::Sha256::h3;
unsigned int gsm::Sha256::h4;
unsigned int gsm::Sha256::h5;
unsigned int gsm::Sha256::h6;
unsigned int gsm::Sha256::h7;
*/
std::string gsm::Sha256::hash_value(std::string msg)
{
    gsm::Sha256::h0 = 0x6a09e667;
    gsm::Sha256::h1 = 0xbb67ae85;
    gsm::Sha256::h2 = 0x3c6ef372;
    gsm::Sha256::h3 = 0xa54ff53a;
    gsm::Sha256::h4 = 0x510e527f;
    gsm::Sha256::h5 = 0x9b05688c;
    gsm::Sha256::h6 = 0x1f83d9ab;
    gsm::Sha256::h7 = 0x5be0cd19;

    std::string message=char_string_to_binary_string(msg,8);
    std::vector<unsigned int> w;
    unsigned int original_message_in_bits_length=message.size();
    message+='1';
    unsigned int k=calculate_k(message.size());    
    for(int i=0;i<k;++i)
    {
        message+='0';
    }
    message+=append_big_endian(original_message_in_bits_length);
    w = extending_16_words_to_64_words(message);
    message = compression(w);
    return message;
}
std::string gsm::Sha256::char_string_to_binary_string(std::string str,unsigned int size)
{
    std::string output="";
    for(char character : str)
    {
        output+=std::bitset<8>(character).to_string();
    }
    return output;
    
}
unsigned int gsm::Sha256::calculate_k(unsigned int message_length_of_bits)
{
    unsigned int number_of_padding=message_length_of_bits/512;
    if(!number_of_padding)
    {
        return 448-message_length_of_bits;
    }
    else
    {
        unsigned int k,pad_number=message_length_of_bits/512;
        k=pad_number*512;
        return (message_length_of_bits-64)-k;
    }
}
std::string gsm::Sha256::append_big_endian(unsigned int message_length_of_bits)
{
    std::string output="";
    output=std::bitset<64>(message_length_of_bits).to_string();
    return output;
}
unsigned int gsm::Sha256::string_of_32bits_to_int(std::string number_as_string)
{
    return stoi(number_as_string,0,2);
}
std::string gsm::Sha256::right_rotation(std::string str,unsigned int rotation_value)
{
    return str.substr(rotation_value,str.size())+str.substr(0,rotation_value);
}
std::vector<unsigned int> gsm::Sha256::extending_16_words_to_64_words(std::string message)
{
    unsigned int number_of_chunks=message.size()/512;
    std::vector<unsigned int> w_vector(64);
    std::string w_string[16];
    unsigned int index=0,j=0;
    for(int i=0;i<number_of_chunks;++i)
    {
        for(j=0,index=0;j<16;++j,++index)
        {
            std::string temp = message.substr(j*32,32);
            w_string[index]=temp;
            w_vector[index]=string_of_32bits_to_int(temp);
            //w[index]=string_of_32bits_to_int(temp);
        }
        unsigned int s0=0,s1=0;
        unsigned int left_side,middle,right_side;
        for(j=16;j<64;++j)
        {
            //s0=(w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
           left_side = integer_right_rotation(w_vector[j-15],7);
           middle = integer_right_rotation(w_vector[j-15],18);
           right_side = w_vector[j-15]>>3;
           s0=(left_side^middle)^right_side;

           //s1=(w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
            left_side = integer_right_rotation(w_vector[j-2],17);
           middle = integer_right_rotation(w_vector[j-2],19);
           right_side = w_vector[j-2]>>10;
           s1=(left_side^middle)^right_side;
           //w[i]=w[i-16]+s0+w[i-7]+s1;
           w_vector[j]=w_vector[j-16]+s0+w_vector[j-7]+s1;

        }
    }
    return w_vector;
}
unsigned int gsm::Sha256::integer_right_rotation(unsigned int number, unsigned int d)
{
    return(number >> d) | (number << (unsigned)(32-d));
}
std::string gsm::Sha256::hex_to_string(unsigned int number)
{
    std::stringstream ss;
    ss << std::hex << number;
    std::string output(ss.str());
    return output;
}
std::string gsm::Sha256::compression(std::vector<unsigned int> w)
{
    unsigned int a,b,c,d,e,f,g,h,s0,s1,ch;
    unsigned int right_side,middle,left_side,temp1, maj, temp2;
    
    a=h0;
    b=h1;
    c=h2;
    d=h3;
    e=h4;
    f=h5;
    g=h6;
    h=h7;

    for(int i=0;i<64;++i)
    {
        //S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        left_side=integer_right_rotation(e,6);
        middle=integer_right_rotation(e,11);
        right_side=integer_right_rotation(e,25);
        s1=left_side^middle^right_side;
       
        //ch := (e and f) xor ((not e) and g)
        left_side=e & f;
        middle=~e;
        right_side=middle & g;
        ch=left_side^right_side;

        // temp1 := h + S1 + ch + k[i] + w[i]
        temp1=h + s1 + ch +table[i]+w[i];
        
        //S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        left_side= integer_right_rotation(a,2);
        middle = integer_right_rotation(a,13);
        right_side = integer_right_rotation(a,22);
        s0=left_side^middle^right_side;
        
        //maj := (a and b) xor (a and c) xor (b and c)
        left_side = a & b;
        middle = a & c;
        right_side = b & c; 
        maj = left_side^middle^right_side;
        temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h0=h0+a;
    h1=h1+b;
    h2=h2+c;
    h3=h3+d;
    h4=h4+e;
    h5=h5+f;
    h6=h6+g;
    h7=h7+h;

    std::string output = hex_to_string(h0) + hex_to_string(h1) 
        + hex_to_string(h2) + hex_to_string(h3) 
        + hex_to_string(h4) + hex_to_string(h5)
        + hex_to_string(h6) + hex_to_string(h7);

    return output;
}
std::string gsm::Sha256::ascii_string_from_binary_string(std::string str)
{
	std::string output="";
	std::stringstream sstream(str);
	while (sstream.good())
	{
		std::bitset<8> bit;
		sstream >> bit;
		if (!sstream.good())
			break;
		char c = char(bit.to_ullong());
		output = output + c;
	}
	return output;
}
