function [ plaintext ] = decrypt_guess(cipherxor, referencetext, row, guesstext)
col = length(referencetext);
guesslen = length(guesstext);
guessResult = zeros(1, guesslen);
for i=1:guesslen
    guessResult(i) = bitxor(cipherxor(row,col+i),guesstext(i)-0);
end
referencetext = cat(2, referencetext, [guessResult]);
plaintext = decrypt_helper( cipherxor, referencetext);
end

