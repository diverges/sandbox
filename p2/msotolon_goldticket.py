#Problem 2.0
import urllib2;

ticket = "0c80353a2c634be44096f9d7977bad4d60dcd000224743105c8eacc3f872e37a2e6c8afdaecba65e8d94754e15a587ea1620cf6b6bc59a0fe5d74400a7cabebbe9fa63236a1a6c90"
oracle = "http://127.0.0.1/oracle.php?ticket=";

print "Decrypting ticket: " + ticket + "\n";

decTicket = ticket.decode("hex");
length = len(decTicket);

print "Ciphertext: " + decTicket;
print "Size: " + str(length);

#### Helper Functions ####

# checks current ticket status
def checkTicket(ticket):
   	 try:
   		 handler = urllib2.urlopen(oracle + ticket);
  		 #if no exception then padding matched
   	 return True;    
   	 except urllib2.URLError as e:
  			 # assume this occurs when padding does not match
   		 return False;

# generates an 8 bytes guess block with the given padding
def generateBlock(guess, padding):
    L = [ 0, 0, 0, 0, 0, 0, 0, 0];

    for x in range(0, padding + 1):
   	 L[7 - x] = padding + 1;

    L[7 - padding] = guess ^ (padding + 1);
    
    return L;

# decrypts a cypher block of 8 bytes
# c0 and c1 should both be 8 bytes
# index defines which block is being overwritten
def decrypt_block(c0, ticket, index):
    i = 0;
    P = [ 0, 0 , 0, 0, 0, 0, 0, 0];
    c1 = ticket[8*index: 8*index + 8]
    
    # byte loop
    while (i < 8):
   	 # guess loop
   	 guess = 2 #ascii value to guess
   	 while (guess < 256):
   		 block = generateBlock(guess, i)
   		 for b in range (0, 8):
   			 block[b] = block[b] ^ P[b];
   			 block[b] = c0[b] ^ block[b];
   		 nt = [];
   		 nt[0:8] = block;
   		 nt[8:16] = c1;
   		 cticket = ''.join(format(x, '02x') for x in nt);
   		 res = checkTicket(cticket);
   		 if (res):
   			 print "Byte: " + str(guess) + " " + chr(guess);
   			 P[7 - i] = guess;
   			 break;
   		 guess += 1;
   	 i += 1;
    return [chr(x) for x in P]

#### Decrypt Ticket ####

# want to decrypt remaining 64 bytes
count = 1; # cipher's decrypted

cypherValues = [ ord(c) for c in decTicket];

decPhrase = []
c0 = cypherValues [0:8];
while (count <= 8):
    decPhrase.extend(decrypt_block(c0, cypherValues, count)); #C(i-1), last cypher
    c0 = cypherValues[8*count: 8*count + 8];
    count += 1;

print 'Decoded Text is: '
print ''.join(decPhrase);

#### Gain admin access
hack = '{"username":"msotolon","is_admin":"true","expired":"2016-01-14"}'
hackValues = [ord(c) for c in hack];
pValues = [ord(x) for x in decPhrase];

print hackValues
print pValues

count = 1;
sol = [0] * 72;
c0 = cypherValues [0:8];
sol[0:8] = c0;
while (count < 8):
    c1 = pValues[8 * count: 8*count + 8];
    c0 = hackValues[8 * count: 8*count + 8];
    for x in range(0, 8):
   	 sol[8*count + x] = c1[x] ^ c0[x]
    count += 1;
print sol

cticket = ''.join(format(x, '02x') for x in sol);
print cticket

try:
  		 handler = urllib2.urlopen(oracle + cticket);
	 #if no exception then padding matched
   	 print 'sending malicious request and got responce: '
    handler.read()
except urllib2.URLError as e:
    print 'error'


