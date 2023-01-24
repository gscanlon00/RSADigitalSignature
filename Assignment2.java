import java.math.BigInteger;
import java.util.Random;
import java.security.MessageDigest;
import java.io.*;

public class Assignment2 {
    
    public static void main(String args[]) throws Exception{
        // Encryption Exponenet
        BigInteger e = BigInteger.valueOf(65537);
        String file = args[0];

        // Create message digest of input file using SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = getDigest(new FileInputStream(file), md, 32);

        // Convert message digest to big int
        BigInteger c = new BigInteger(1,digest);

        // Generate numbers in array ([p, q, n, phi])
        BigInteger numsAr[] = genNums();
        boolean relPrime = false;

        // Check if e is relatively prime to phi(n). If not generate new values and try again (i.e gcd(phi e) = 1)
        do {
            BigInteger result = euclidAlgo(numsAr[3], e);

            // If GCD is 1, numbers are relatively prime so we break loop.
            if (result.compareTo(BigInteger.ONE) == 0) {
                relPrime = true;
            } else {
                // If numbers are not relatively prime, recalcuate numbers
                numsAr = genNums();
            }
        } while(!relPrime);

        BigInteger p = numsAr[0];
        BigInteger q = numsAr[1];
        BigInteger n = numsAr[2];
        BigInteger phi = numsAr[3];

        // Convert public key n to hexadecimal and output to file
        String publicKey = n.toString(16);
        writeToFile(publicKey, "Modulus.txt");

        // Create secret key d with extended euclidean algorithm method (e (mod phi(n)))
        BigInteger d = extendedEuc(phi, e);

        // Generate signature using Chinese remainder theorem
        BigInteger sig = CRT(p, q, n, c, d);

        // Verify signature is valid (v = s^e (mod n))
        BigInteger ver = CRT(p, q, n, sig, e);

        // If signature is valid, ver will be equal to c (original message digest)
        if (c.equals(ver)) {
            // Convert signature to hexadecimal string
            String hexSig = sig.toString(16);

            // Output signature
            System.out.println(hexSig);
        } else {
            throw new Exception("The signature generated was not valid.");
        }
    }

    // Method to generate the numbers for p, q, n and phi
    public static BigInteger[] genNums() {
        // Generate probable prime number p which is 512-bits long
        BigInteger p = BigInteger.probablePrime(512, new Random());
        boolean notEqual = false;

        // Generate second probable prime q
        BigInteger q = BigInteger.probablePrime(512, new Random());
        // If q is not distinct from p, generate q again
        while(!notEqual){
            if (q.compareTo(p) != 0) {
                notEqual = true;
                q = BigInteger.probablePrime(512, new Random());
            }
        }
        // Product of prime numbers = public key n
        BigInteger n = p.multiply(q);

        // Subtract 1 from prime numbers to use in phi calcuation
        BigInteger p2 = p.subtract(BigInteger.ONE);
        BigInteger q2 = q.subtract(BigInteger.ONE);

        // Calcuating phi(n)
        BigInteger phi = p2.multiply(q2);

        // Return numbers in array
        BigInteger ar[] = new BigInteger[]{p, q, n, phi};
        return ar;
    }

    // Euclidean algorithm to verify that exponent and phi(n) are relatively prime
    public static BigInteger euclidAlgo(BigInteger phi, BigInteger e) {
        // Loop until a or b = 0
        while(true){

            // If phi is zero then gcd is e
            if (phi.compareTo(BigInteger.ZERO) == 0) {
                return e;
            }
            // If e is zero then gcd is phi
            if (e.compareTo(BigInteger.ZERO) == 0) {
                return phi;
            }

            BigInteger ba[] = phi.divideAndRemainder(e);
            phi = e;
            e = ba[1];
        }
    }

    // Extended Euclidean Algorithm to calcuate multiplicative inverse (e (mod phi(n)))
    public static BigInteger extendedEuc(BigInteger phi, BigInteger e) {
        BigInteger quot;
        BigInteger remain;
        BigInteger t;
        BigInteger d = BigInteger.ZERO;
        BigInteger t2 = BigInteger.ONE;
        
        // While e and phi are greater than 0, continue looping
        while(e.compareTo(BigInteger.ZERO) == 1){
            BigInteger ba[] = phi.divideAndRemainder(e);
            quot = ba[0];
            remain = ba[1];
            t = d.subtract(t2.multiply(quot));

            phi = e;
            e = remain;
            d = t2;
            t2 = t;
        }

        // If d is not positive add to last t2 value
        if (d.compareTo(BigInteger.ZERO) == -1) {
            d = d.add(t2);
        } 
        return d;
    }

    // Square and multiply algorithm to handle exponentiation
    public static BigInteger squareMult(BigInteger expo, BigInteger base, BigInteger mod) {

        // Convert exponent to binary so that we can loop through
        String binExpo = expo.toString(2);
        BigInteger y = base;

        // Loop through bits. Start at second bit 
        for (int i = 1; i < binExpo.length(); i++){
            char bit = binExpo.charAt(i);

            y = (y.multiply(y)).mod(mod);

            if (bit == '1'){
                y = (y.multiply(base)).mod(mod);
            }
        }
        return y;
    }

    // CRT Implementation to decrypt message
    public static BigInteger CRT(BigInteger p, BigInteger q, BigInteger n, BigInteger c, BigInteger d) {
        BigInteger result;

        // P and q are prime factors of n. Get the multiplicative inverse c mod q, c mod p
        BigInteger dq = extendedEuc(q, c);
        BigInteger dp = extendedEuc(p, c);

        // Calcuate a1 and a2 using square and multiply algorithm (d^dq (mod q))
        BigInteger a1 = squareMult(d, dq, q);
        BigInteger a2 = squareMult(d, dp, p);

        // Calcuate multiplicative inverses of p and q
        BigInteger invp = extendedEuc(q, p);
        BigInteger invq = extendedEuc(p, q);

        // result =(a1*M1*invM1 + a2*M2*invM2) where:
        // M1=p M2=q a1=dq^d  a2=dp^d  invM1=extendedEuc(q, p) invM2=extendedEuc(p, q)

        BigInteger eq1 = (a1.multiply(p)).multiply(invp);
        BigInteger eq2 = (a2.multiply(q)).multiply(invq);
        result = eq1.add(eq2);
        result = extendedEuc(n, result);

        return result;
    }

    // Method used to convert input file into message digest
    public static byte[] getDigest(InputStream is, MessageDigest md, int byteArraySize) throws Exception {
		md.reset();
		byte[] bytes = new byte[byteArraySize];
		int numBytes;
		while ((numBytes = is.read(bytes)) != -1) {
			md.update(bytes, 0, numBytes);
		}
		byte[] digest = md.digest();
		return digest;
	}

    // Method for creating and writing to file. Use for writing public key to file.
    public static void writeToFile(String input, String fileName) throws Exception{
        
        File fileObj = new File(fileName);
        fileObj.createNewFile();

        FileWriter writer = new FileWriter(fileName);
        writer.write(input);
        writer.close();
    }
}