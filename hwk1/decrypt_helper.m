function [ plaintext ] = decrypt_helper( cipherxor, referencetext )
len = length(referencetext);
[ct_num, ~] = size(cipherxor);
plaintext = zeros(ct_num+1, len);

for i=1:len
    tmp = referencetext(i)-0;
    plaintext(:,i) = cat(1, bitxor(cipherxor(:,i), tmp), [tmp]);
end

end

