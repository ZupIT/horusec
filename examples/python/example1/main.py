secret = 'password123!'

password = 'thisisnotapassword' #nohorus

command = 'print "this command is not secure!!"'

exec(command)

print(secret)

assert 2 + 2 == 5, "Wrong!"
