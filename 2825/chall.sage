import signal
signal.alarm(300)

F = GF(0xdead1337cec2a21ad8d01f0ddabce77f57568d649495236d18df76b5037444b1)
A = random_matrix(F, 52)[:,:-3]
print(dumps(A).hex())

set_random_seed(input(version() + "\nseed: "))
if A == random_matrix(F, 52)[:,:-3]:
	print("DH{}")