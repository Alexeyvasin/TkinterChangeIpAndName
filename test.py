
fhand = open("getlic.txt", "r")
ftext = fhand.read()
crypttext=''
for chr in ftext:
	crypttext += str(ord(chr))
	crypttext +=str(ord('!'))
	crypttext +=str(ord('*'))
	crypttext +=str(ord('&'))
#message(ord('!'))
#message(ord('*'))
#message(ord('&'))
fhand.close()
fhand = open("Rename.lic", "w")
fhand.write(crypttext)
fhand.close()