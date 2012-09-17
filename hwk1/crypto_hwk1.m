c = [
%ciphertext #1:
sscanf('315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba50', '%2x')';
%ciphertext #2:
sscanf('234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb741', '%2x')';
%ciphertext #3:
sscanf('32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de812', '%2x')';
%ciphertext #4:
sscanf('32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee41', '%2x')';
%ciphertext #5:
sscanf('3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de812', '%2x')';
%ciphertext #6:
sscanf('32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d', '%2x')';
%ciphertext #7:
sscanf('32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af513', '%2x')';
%ciphertext #8:
sscanf('315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e941', '%2x')';
%ciphertext #9:
sscanf('271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f404', '%2x')';
%ciphertext #10:
sscanf('466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d', '%2x')';
%target ciphertext (decrypt this one):
sscanf('32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904', '%2x')']

[ct_num, ct_len] = size(c);
z = zeros(ct_num-1, ct_len);

% xc(n) is target ciphertext ^ ciphertext(n) -- Note: we could start with a
% different 'reference' ciphertext if we wanted...
xc = z;
for i = 1:ct_num-1
    xc(i,:) = bitxor(c(ct_num,:), c(i,:));
end

% Classification of ascii by groups based on quick inspection
% 0001 XXXX, 0-31, formatting
% 0010 XXXX, 32-47, punctuation
% 0011 XXXX, 48-63, numbers and punctuation
% 010X XXXX, 64-95, upper case
% 011X XXXX, 96-127, lower case
%  Assumption 1: probably dealing with non-formatting ascii

% Take the xor of the cts and bitand with 0xE0 to hopefully reveal spaces
% spaces should appear at places where columns have the most '64' values.
%  Result: looks like we have spaces at index 4, 11, 14 or 15, 19, etc.
bitand(xc, 224)

% The first word is three letters, maybe 'The '? Let's xor the xor of the
% cts and see if the rest of the cts make any kind of sense.
%  Result:
%     1234
% 1   We c
% 2   Eule
% 3   The 
% 4   The 
% 5   You 
% 6   Ther
% 7   Ther
% 8   We c
% 9   A (p
% 10   The
% 11  The 
%   These seem to be pretty good...
char(decrypt_helper(xc, 'The '));

% CT 6 and 7 appear to be 'There ' so let's get the 5th and 6th letter of
% our target verify the same result, then recompute the rest of the 5th and
% 6th letter of each string
%  Result:
%   Both 6 and 7 result in 'se'
%     123456
% 1   We can
% 2   Euler 
% 3   The ni
% 4   The ci
% 5   You dd
% 6   There 
% 7   There 
% 8   We can
% 9   A (pri
% 10   The C
% 11 'The se'
bitxor(xc(6:7,5),'e'-0);
bitxor(xc(6:7,6),' '-0);
char(decrypt_helper(xc, 'The se'));

% At this point, this method seems to be working.  It was worth the effort
% to create decrypt_guess and decrypt_helper to hopefully speed things up
% Verify functions do the right thing...
char(decrypt_guess(xc, 'The se', 1, ' '));

% Now we just keep going until we resolve each character; it should be
% pretty obvious when we guess wrong...
char(decrypt_guess(xc, 'The sec', 9, 'a'));
char(decrypt_guess(xc, 'The secr', 4, 'e'));
char(decrypt_helper(xc, 'The secret '));
char(decrypt_guess(xc, 'The secret m', 4, 'x'));
char(decrypt_guess(xc, 'The secret me', 1, ' '));
char(decrypt_helper(xc, 'The secret message '));
char(decrypt_guess(xc, 'The secret message ', 2, 'y'));
char(decrypt_guess(xc, 'The secret message i', 2, ' '));
char(decrypt_guess(xc, 'The secret message is', 4, 'e'));
char(decrypt_helper(xc, 'The secret message is: '));
char(decrypt_guess(xc, 'The secret message is: ', 1, 'r'));
char(decrypt_guess(xc, 'The secret message is: W', 2, 'o'));
char(decrypt_guess(xc, 'The secret message is: Wh', 2, 'y'));
char(decrypt_guess(xc, 'The secret message is: Whe', 2, ' '));
char(decrypt_helper(xc, 'The secret message is: When '));
char(decrypt_guess(xc, 'The secret message is: When ', 10, 'y '));
char(decrypt_guess(xc, 'The secret message is: When us', 7, 'aphy'));
char(decrypt_guess(xc, 'The secret message is: When using ', 6, 'y'));
char(decrypt_guess(xc, 'The secret message is: When using a', 10, ') '));
char(decrypt_guess(xc, 'The secret message is: When using a s', 4, 'ryption '));
char(decrypt_helper(xc, 'The secret message is: When using a stream cipher'));
char(decrypt_guess(xc, 'The secret message is: When using a stream cipher', 4, 'rithm'));
char(decrypt_helper(xc, 'The secret message is: When using a stream cipher, never '));
char(decrypt_guess(xc, 'The secret message is: When using a stream cipher, never ', 1, 'n '));
char(decrypt_helper(xc, 'The secret message is: When using a stream cipher, never use '));
char(decrypt_guess(xc, 'The secret message is: When using a stream cipher, never use ', 7, 'nment '));
char(decrypt_guess(xc, 'The secret message is: When using a stream cipher, never use the ke', 1, 'tor '));
char(decrypt_helper(xc, 'The secret message is: When using a stream cipher, never use the key more than '));
char(decrypt_guess(xc, 'The secret message is: When using a stream cipher, never use the key more than ', 1, 'er'));
char(decrypt_helper(xc, 'The secret message is: When using a stream cipher, never use the key more than once'));

% Viola
p = decrypt_helper(xc, 'The secret message is: When using a stream cipher, never use the key more than once');
char(p(11,:))

% We could continue decrypting the other messages but once we run out of
% characters in a ciphertext, we can no longer use that ciphertext as a
% reference.