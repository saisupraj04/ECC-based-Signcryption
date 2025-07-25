from flask import *
import random

app=Flask(__name__)

def points_on_curve(a,b,p):
	qr=list()
	for i in range(p):
		qr.append(i**2%p)
	points = []
	for x in range(p):
		y_squared = (x**3 + a * x + b) % p
		if y_squared in qr:
			y = qr.index(y_squared)
			points.append((x, y))
			if y != 0:
				points.append((x, p - y))
	return points


def base_point_order(*parameters):
	i=1
	
	if len(parameters)==5:
		(x2,y2,a,b,p)=parameters
		stop=len(points_on_curve(a,b,p))
		opt=1

	elif len(parameters)==6:
		(x2,y2,a,b,p,stop)=parameters
		opt=2
		stop%=len(base_point_order(x2,y2,a,b,p))+1

	stop%=(len(points_on_curve(a,b,p))+1)
	points=[(x2,y2)]

	if stop==1:
		return points[0]
	
	if y2==0:
		if opt==2:
			return points[0]
		return points


	lamda = (3*(x2**2) + a) * pow((2*y2),-1,p)%p
	x3=(lamda**2-2*x2)%p
	y3=(lamda*(x2-x3)-y2)%p

	i+=1

	points.append((x3,y3))

	(x1,y1)=(x3,y3)

	while i<stop+1:
		if x2!=x1:	
			lamda=((y1-y2)*pow((x1-x2),-1,p))%p

			x3=(lamda**2-x1-x2)%p
			y3=(lamda*(x1-x3)-y1)%p

			points.append((x3,y3))

			(x1,y1)=(x3,y3)
			
			if i==stop:
				return points[stop-1]

			i+=1

		else:
			if i==stop and opt==2:
				return points[stop-1]
			i+=1
			return points


def possible_base_points(x2,y2,a,b,q):
	pbs=[]
	for i in (points_on_curve(a,b,q)):

			(x2,y2)=i

			if is_prime(len(base_point_order(x2,y2,a,q))+1):
				pbs.append((x2,y2))
	return pbs

def unsigncrypt(sigma,PKs,PKr,SKr,q,n,a,b):
	(c,e,s)=sigma
	w=pow(s,-1,n)
	x1=base_point_order(PKr[0],PKr[1],a,b,q,e*w)
	x2=base_point_order(PKs[0],PKs[1],a,b,q,w*SKr)
	if x1==None and x2==None:
		return None
	elif x1==None:
		X=x2
	elif x2==None:
		X=x1
	else:
		X=points_add(x1,x2,a,b,q)
	b1=Hash1(X[0])
	b1=int(b1,2)
	m=b1^c
	e1=Hash2(bin(m)[2:],X,PKs,PKr,q)
	if e==e1:
		return m
	else:
		return "⊥" #symbol ⊥ demonstrates that the attempted decryption of a ciphertext that does not pass the authenticity check 

def signcrypt(PKs,PKr,SKs,m,n,a,b,q):
	set=True
	count=0
	while set:
		k=random.randint(1,n-1)
		K=base_point_order(PKr[0],PKr[1],a,b,q,k)
		b=Hash1(K[0])
		b=int(b,2)
		c=b^m
		e=Hash2(bin(m)[2:],K,PKs,PKr,q)
		s=(pow(k,-1,n)*(e+SKs))%n
		if s!=0:
			set=False
	sigma=(c,e,s)			

	return sigma

def points_add(p1,p2,a,b,q):
	(x1,y1)=p1
	(x2,y2)=p2
	if p1!=p2:
		lamda=((y1-y2)*pow((x1-x2),-1,q))%q
		x3=(lamda**2-x1-x2)%q
		y3=(lamda*(x1-x3)-y1)%q
	else:
		(x3,y3)=base_point_order(x1,y1,a,b,q,2)

	return x3,y3

def KeyGen(P,a,b,p,SKs,SKr):
	(x,y)= P
	PKs=base_point_order(x,y,a,b,p,SKs)
	PKr=base_point_order(x,y,a,b,p,SKr)
	return PKs,PKr

def is_prime(n):
  if n == 2 or n == 3: return True
  if n < 2 or n%2 == 0: return False
  if n < 9: return True
  if n%3 == 0: return False
  r = int(n**0.5)
  # since all primes > 3 are of the form 6n ± 1
  # start with f=5 (which is prime)
  # and test f, f+2 for being prime
  # then loop by 6. 
  f = 5
  while f <= r:
    if n % f == 0: return False
    if n % (f+2) == 0: return False
    f += 6
  return True 

def Hash2(binary_string, point1, point2, point3, prime_q):
    # Custom hash function using basic operations
    hash_value = 0

    # Process binary string
    for char in binary_string:
        hash_value = (hash_value * 31 + ord(char)) % prime_q

    # Process curve points
    for point in [point1, point2, point3]:
        hash_value = (hash_value * 31 + point[0]) % prime_q
        hash_value = (hash_value * 31 + point[1]) % prime_q

    return hash_value

def Hash1(input_number):

    hash_value = (input_number * 7) % 32

    return bin(hash_value)[2:]

@app.route('/')
def welcome():
	return render_template('index.html')

@app.route('/points',methods=['POST'])
def gen_point():
	possible_base_points=[]
	a = int(request.form['inputA'])
	b = int(request.form['inputB'])
	q = int(request.form['inputQ'])

	if (4*(a**3)+27*(b**2))%q==0:
		exit(0)

	for i in (points_on_curve(a,b,q)):

		(x2,y2)=i

		if is_prime(len(base_point_order(x2,y2,a,b,q))+1):
			possible_base_points.append([(x2,y2),len(base_point_order(x2,y2,a,b,q))+1])	
	return render_template('points.html',points=possible_base_points,a=a,b=b,q=q)

@app.route('/sign',methods=['GET','POST'])
def sig_crypt():
	p = request.form['enteredPoint'].split(',')
	q = int(p[0][1:])
	r = int(p[1][:-1])
	(x2,y2) = (q,r)
	SKs = int(request.form['senderSecretKey'])
	SKr = int(request.form['receiverSecretKey'])
	m = int(request.form['message'])
	a = int(request.form['inputA'])
	b = int(request.form['inputB'])
	q = int(request.form['inputQ'])

	PKs,PKr=KeyGen((x2,y2),a,b,q,SKs,SKr)

	n=(len(base_point_order(x2,y2,a,b,q))+1)

	l=len(bin(q)[2:])

	sigma=signcrypt(PKs,PKr,SKs,m,n,a,b,q)

	return render_template('unsigncrypt.html',sigma=sigma,P=(x2,y2),PKs=PKs,PKr=PKr,SKs=SKs,SKr=SKr,m=m,n=n,a=a,b=b,q=q,l=l)

@app.route('/resign',methods=['POST'])
def resign():
	message = request.form['signature'].split(',')
	t = int(message[0][1:])
	r = int(message[1])
	s = int(message[2][:-1])
	sigma = (t,r,s)
	n = int(request.form['n'])
	a = int(request.form['inputA'])
	b = int(request.form['inputB'])
	q = int(request.form['inputQ'])
	PKs = request.form['senderPublicKey'].split(',')
	x = int(PKs[0][1:])
	y = int(PKs[1][:-1])
	PKs = (x,y)
	PKr = request.form['receiverPublicKey'].split(',')
	d = int(PKr[0][1:])
	e = int(PKr[1][:-1])
	PKr = (d,e)
	SKr = int(request.form['receiverSecretKey'])

	m1 =unsigncrypt(sigma,PKs,PKr,SKr,q,n,a,b)

	return render_template('recover.html',m1=m1)

if __name__ == '__main__':
    app.run(debug=True,port=4000)
			