
module Serpent

export Serpent128

type Serpent128
    key::Array{Int64, 2}
    buffer::Array{UInt8}
    bits::Int64
    encrypt::Function
    decrypt::Function

    Serpent128(key::ASCIIString) = begin
        new(makekey(stringtobytearray(key)), zeros(UInt8), 128, encrypt, decrypt) 
    end
    Serpent128(key::Array{UInt8}) = begin
        new(makekey(key), zeros(UInt8), encrypt, decrypt) 
    end
end

function LL (x)
    return convert(UInt8, x)
end

function tripleshift(a::Integer, b::Integer)
    return a >>> (b % 32)  
end

sbox = Array([[ LL(3); LL(8);LL(15); LL(1);LL(10); LL(6); LL(5);LL(11);LL(14);LL(13); LL(4); LL(2); LL(7); LL(0); LL(9);LL(12) ] [LL(15);LL(12); LL(2); LL(7); LL(9); LL(0); LL(5);LL(10); LL(1);LL(11);LL(14); LL(8); LL(6);LL(13); LL(3); LL(4) ] [ LL(8); LL(6); LL(7); LL(9); LL(3);LL(12);LL(10);LL(15);LL(13); LL(1);LL(14); LL(4); LL(0);LL(11); LL(5); LL(2) ] [ LL(0);LL(15);LL(11); LL(8);LL(12); LL(9); LL(6); LL(3);LL(13); LL(1); LL(2); LL(4);LL(10); LL(7); LL(5);LL(14) ] [ LL(1);LL(15); LL(8); LL(3);LL(12); LL(0);LL(11); LL(6); LL(2); LL(5); LL(4);LL(10); LL(9);LL(14); LL(7);LL(13) ] [LL(15); LL(5); LL(2);LL(11); LL(4);LL(10); LL(9);LL(12); LL(0); LL(3);LL(14); LL(8);LL(13); LL(6); LL(7); LL(1) ] [ LL(7); LL(2);LL(12); LL(5); LL(8); LL(4); LL(6);LL(11);LL(14); LL(9); LL(1);LL(15);LL(13); LL(3);LL(10); LL(0) ] [ LL(1);LL(13);LL(15); LL(0);LL(14); LL(8); LL(2);LL(11); LL(7); LL(4);LL(12);LL(10); LL(9); LL(3); LL(5); LL(6) ] [ LL(3); LL(8);LL(15); LL(1);LL(10); LL(6); LL(5);LL(11);LL(14);LL(13); LL(4); LL(2); LL(7); LL(0); LL(9);LL(12) ] [LL(15);LL(12); LL(2); LL(7); LL(9); LL(0); LL(5);LL(10); LL(1);LL(11);LL(14); LL(8); LL(6);LL(13); LL(3); LL(4) ] [ LL(8); LL(6); LL(7); LL(9); LL(3);LL(12);LL(10);LL(15);LL(13); LL(1);LL(14); LL(4); LL(0);LL(11); LL(5); LL(2) ] [ LL(0);LL(15);LL(11); LL(8);LL(12); LL(9); LL(6); LL(3);LL(13); LL(1); LL(2); LL(4);LL(10); LL(7); LL(5);LL(14) ] [ LL(1);LL(15); LL(8); LL(3);LL(12); LL(0);LL(11); LL(6); LL(2); LL(5); LL(4);LL(10); LL(9);LL(14); LL(7);LL(13) ] [LL(15); LL(5); LL(2);LL(11); LL(4);LL(10); LL(9);LL(12); LL(0); LL(3);LL(14); LL(8);LL(13); LL(6); LL(7); LL(1) ] [ LL(7); LL(2);LL(12); LL(5); LL(8); LL(4); LL(6);LL(11);LL(14); LL(9); LL(1);LL(15);LL(13); LL(3);LL(10); LL(0) ] [ LL(1);LL(13);LL(15); LL(0);LL(14); LL(8); LL(2);LL(11); LL(7); LL(4);LL(12);LL(10); LL(9); LL(3); LL(5); LL(6) ] [ LL(3); LL(8);LL(15); LL(1);LL(10); LL(6); LL(5);LL(11);LL(14);LL(13); LL(4); LL(2); LL(7); LL(0); LL(9);LL(12) ] [LL(15);LL(12); LL(2); LL(7); LL(9); LL(0); LL(5);LL(10); LL(1);LL(11);LL(14); LL(8); LL(6);LL(13); LL(3); LL(4) ] [ LL(8); LL(6); LL(7); LL(9); LL(3);LL(12);LL(10);LL(15);LL(13); LL(1);LL(14); LL(4); LL(0);LL(11); LL(5); LL(2) ] [ LL(0);LL(15);LL(11); LL(8);LL(12); LL(9); LL(6); LL(3);LL(13); LL(1); LL(2); LL(4);LL(10); LL(7); LL(5);LL(14) ] [ LL(1);LL(15); LL(8); LL(3);LL(12); LL(0);LL(11); LL(6); LL(2); LL(5); LL(4);LL(10); LL(9);LL(14); LL(7);LL(13) ] [LL(15); LL(5); LL(2);LL(11); LL(4);LL(10); LL(9);LL(12); LL(0); LL(3);LL(14); LL(8);LL(13); LL(6); LL(7); LL(1) ] [ LL(7); LL(2);LL(12); LL(5); LL(8); LL(4); LL(6);LL(11);LL(14); LL(9); LL(1);LL(15);LL(13); LL(3);LL(10); LL(0) ] [ LL(1);LL(13);LL(15); LL(0);LL(14); LL(8); LL(2);LL(11); LL(7); LL(4);LL(12);LL(10); LL(9); LL(3); LL(5); LL(6) ] [ LL(3); LL(8);LL(15); LL(1);LL(10); LL(6); LL(5);LL(11);LL(14);LL(13); LL(4); LL(2); LL(7); LL(0); LL(9);LL(12) ] [LL(15);LL(12); LL(2); LL(7); LL(9); LL(0); LL(5);LL(10); LL(1);LL(11);LL(14); LL(8); LL(6);LL(13); LL(3); LL(4) ] [ LL(8); LL(6); LL(7); LL(9); LL(3);LL(12);LL(10);LL(15);LL(13); LL(1);LL(14); LL(4); LL(0);LL(11); LL(5); LL(2) ] [ LL(0);LL(15);LL(11); LL(8);LL(12); LL(9); LL(6); LL(3);LL(13); LL(1); LL(2); LL(4);LL(10); LL(7); LL(5);LL(14) ] [ LL(1);LL(15); LL(8); LL(3);LL(12); LL(0);LL(11); LL(6); LL(2); LL(5); LL(4);LL(10); LL(9);LL(14); LL(7);LL(13) ] [LL(15); LL(5); LL(2);LL(11); LL(4);LL(10); LL(9);LL(12); LL(0); LL(3);LL(14); LL(8);LL(13); LL(6); LL(7); LL(1) ] [ LL(7); LL(2);LL(12); LL(5); LL(8); LL(4); LL(6);LL(11);LL(14); LL(9); LL(1);LL(15);LL(13); LL(3);LL(10); LL(0) ] [ LL(1);LL(13);LL(15); LL(0);LL(14); LL(8); LL(2);LL(11); LL(7); LL(4);LL(12);LL(10); LL(9); LL(3); LL(5); LL(6) ] ])

inverse_sbox = Array([ [LL(13); LL(3);LL(11); LL(0); LL(10); LL(6); LL(5);LL(12); LL(1);LL(14); LL(4); LL(7);LL(15); LL(9); LL(8); LL(2) ]  [ LL(5); LL(8); LL(2);LL(14);LL(15); LL(6);LL(12); LL(3);LL(11); LL(4); LL(7); LL(9); LL(1);LL(13);LL(10); LL(0) ]  [LL(12); LL(9);LL(15); LL(4);LL(11);LL(14); LL(1); LL(2); LL(0); LL(3); LL(6);LL(13); LL(5); LL(8);LL(10); LL(7) ]  [ LL(0); LL(9);LL(10); LL(7);LL(11);LL(14); LL(6);LL(13); LL(3); LL(5);LL(12); LL(2); LL(4); LL(8);LL(15); LL(1) ]  [ LL(5); LL(0); LL(8); LL(3);LL(10); LL(9); LL(7);LL(14); LL(2);LL(12);LL(11); LL(6); LL(4);LL(15);LL(13); LL(1) ]  [ LL(8);LL(15); LL(2); LL(9); LL(4); LL(1);LL(13);LL(14);LL(11); LL(6); LL(5); LL(3); LL(7);LL(12);LL(10); LL(0) ]  [LL(15);LL(10); LL(1);LL(13); LL(5); LL(3); LL(6); LL(0); LL(4); LL(9);LL(14); LL(7); LL(2);LL(12); LL(8);LL(11) ]  [ LL(3); LL(0); LL(6);LL(13); LL(9);LL(14);LL(15); LL(8); LL(5);LL(12);LL(11); LL(7);LL(10); LL(1); LL(4); LL(2) ]  [LL(13); LL(3);LL(11); LL(0);LL(10); LL(6); LL(5);LL(12); LL(1);LL(14); LL(4); LL(7);LL(15); LL(9); LL(8); LL(2) ]  [ LL(5); LL(8); LL(2);LL(14);LL(15); LL(6);LL(12); LL(3);LL(11); LL(4); LL(7); LL(9); LL(1);LL(13);LL(10); LL(0) ]  [LL(12); LL(9);LL(15); LL(4);LL(11);LL(14); LL(1); LL(2); LL(0); LL(3); LL(6);LL(13); LL(5); LL(8);LL(10); LL(7) ]  [ LL(0); LL(9);LL(10); LL(7);LL(11);LL(14); LL(6);LL(13); LL(3); LL(5);LL(12); LL(2); LL(4); LL(8);LL(15); LL(1) ]  [ LL(5); LL(0); LL(8); LL(3);LL(10); LL(9); LL(7);LL(14); LL(2);LL(12);LL(11); LL(6); LL(4);LL(15);LL(13); LL(1) ]  [ LL(8);LL(15); LL(2); LL(9); LL(4); LL(1);LL(13);LL(14);LL(11); LL(6); LL(5); LL(3); LL(7);LL(12);LL(10); LL(0) ]  [LL(15);LL(10); LL(1);LL(13); LL(5); LL(3); LL(6); LL(0); LL(4); LL(9);LL(14); LL(7); LL(2);LL(12); LL(8);LL(11) ]  [ LL(3); LL(0); LL(6);LL(13); LL(9);LL(14);LL(15); LL(8); LL(5);LL(12);LL(11); LL(7);LL(10); LL(1); LL(4); LL(2) ]  [LL(13); LL(3);LL(11); LL(0);LL(10); LL(6); LL(5);LL(12); LL(1);LL(14); LL(4); LL(7);LL(15); LL(9); LL(8); LL(2) ]  [ LL(5); LL(8); LL(2);LL(14);LL(15); LL(6);LL(12); LL(3);LL(11); LL(4); LL(7); LL(9); LL(1);LL(13);LL(10); LL(0) ]  [LL(12); LL(9);LL(15); LL(4);LL(11);LL(14); LL(1); LL(2); LL(0); LL(3); LL(6);LL(13); LL(5); LL(8);LL(10); LL(7) ]  [ LL(0); LL(9);LL(10); LL(7);LL(11);LL(14); LL(6);LL(13); LL(3); LL(5);LL(12); LL(2); LL(4); LL(8);LL(15); LL(1) ]  [ LL(5); LL(0); LL(8); LL(3);LL(10); LL(9); LL(7);LL(14); LL(2);LL(12);LL(11); LL(6); LL(4);LL(15);LL(13); LL(1) ]  [ LL(8);LL(15); LL(2); LL(9); LL(4); LL(1);LL(13);LL(14);LL(11); LL(6); LL(5); LL(3); LL(7);LL(12);LL(10); LL(0) ]  [LL(15);LL(10); LL(1);LL(13); LL(5); LL(3); LL(6); LL(0); LL(4); LL(9);LL(14); LL(7); LL(2);LL(12); LL(8);LL(11) ]  [ LL(3); LL(0); LL(6);LL(13); LL(9);LL(14);LL(15); LL(8); LL(5);LL(12);LL(11); LL(7);LL(10); LL(1); LL(4); LL(2) ]  [LL(13); LL(3);LL(11); LL(0);LL(10); LL(6); LL(5);LL(12); LL(1);LL(14); LL(4); LL(7);LL(15); LL(9); LL(8); LL(2) ]  [ LL(5); LL(8); LL(2);LL(14);LL(15); LL(6);LL(12); LL(3);LL(11); LL(4); LL(7); LL(9); LL(1);LL(13);LL(10); LL(0) ]  [LL(12); LL(9);LL(15); LL(4);LL(11);LL(14); LL(1); LL(2); LL(0); LL(3); LL(6);LL(13); LL(5); LL(8);LL(10); LL(7) ]  [ LL(0); LL(9);LL(10); LL(7);LL(11);LL(14); LL(6);LL(13); LL(3); LL(5);LL(12); LL(2); LL(4); LL(8);LL(15); LL(1) ]  [ LL(5); LL(0); LL(8); LL(3);LL(10); LL(9); LL(7);LL(14); LL(2);LL(12);LL(11); LL(6); LL(4);LL(15);LL(13); LL(1) ]  [ LL(8);LL(15); LL(2); LL(9); LL(4); LL(1);LL(13);LL(14);LL(11); LL(6); LL(5); LL(3); LL(7);LL(12);LL(10); LL(0) ]  [LL(15);LL(10); LL(1);LL(13); LL(5); LL(3); LL(6); LL(0); LL(4); LL(9);LL(14); LL(7); LL(2);LL(12); LL(8);LL(11) ]  [ LL(3); LL(0); LL(6);LL(13); LL(9);LL(14);LL(15); LL(8); LL(5);LL(12);LL(11); LL(7);LL(10); LL(1); LL(4); LL(2) ] ])

iptable = Array( [ LL(0); LL(32); LL(64); LL(96); LL(1); LL(33); LL(65); LL(97); LL(2); LL(34); LL(66); LL(98); LL(3); LL(35); LL(67); LL(99); LL(4); LL(36); LL(68); LL(100); LL(5); LL(37); LL(69); LL(101); LL(6); LL(38); LL(70); LL(102); LL(7); LL(39); LL(71); LL(103); LL(8); LL(40); LL(72); LL(104); LL(9); LL(41); LL(73); LL(105); LL(10); LL(42); LL(74); LL(106); LL(11); LL(43); LL(75); LL(107); LL(12); LL(44); LL(76); LL(108); LL(13); LL(45); LL(77); LL(109); LL(14); LL(46); LL(78); LL(110); LL(15); LL(47); LL(79); LL(111); LL(16); LL(48); LL(80); LL(112); LL(17); LL(49); LL(81); LL(113); LL(18); LL(50); LL(82); LL(114); LL(19); LL(51); LL(83); LL(115); LL(20); LL(52); LL(84); LL(116); LL(21); LL(53); LL(85); LL(117); LL(22); LL(54); LL(86); LL(118); LL(23); LL(55); LL(87); LL(119); LL(24); LL(56); LL(88); LL(120); LL(25); LL(57); LL(89); LL(121); LL(26); LL(58); LL(90); LL(122); LL(27); LL(59); LL(91); LL(123); LL(28); LL(60); LL(92); LL(124); LL(29); LL(61); LL(93); LL(125); LL(30); LL(62); LL(94); LL(126); LL(31); LL(63); LL(95); LL(127)])

fptable = Array([ LL(0); LL(4); LL(8); LL(12); LL(16); LL(20); LL(24); LL(28); LL(32); LL(36); LL(40); LL(44); LL(48); LL(52); LL(56); LL(60); LL(64); LL(68); LL(72); LL(76); LL(80); LL(84); LL(88); LL(92); LL(96); LL(100); LL(104); LL(108); LL(112); LL(116); LL(120); LL(124); LL(1); LL(5); LL(9); LL(13); LL(17); LL(21); LL(25); LL(29); LL(33); LL(37); LL(41); LL(45); LL(49); LL(53); LL(57); LL(61); LL(65); LL(69); LL(73); LL(77); LL(81); LL(85); LL(89); LL(93); LL(97); LL(101); LL(105); LL(109); LL(113); LL(117); LL(121); LL(125); LL(2); LL(6); LL(10); LL(14); LL(18); LL(22); LL(26); LL(30); LL(34); LL(38); LL(42); LL(46); LL(50); LL(54); LL(58); LL(62); LL(66); LL(70); LL(74); LL(78); LL(82); LL(86); LL(90); LL(94); LL(98); LL(102); LL(106); LL(110); LL(114); LL(118); LL(122); LL(126); LL(3); LL(7); LL(11); LL(15); LL(19); LL(23); LL(27); LL(31); LL(35); LL(39); LL(43); LL(47); LL(51); LL(55); LL(59); LL(63); LL(67); LL(71); LL(75); LL(79); LL(83); LL(87); LL(91); LL(95); LL(99); LL(103); LL(107); LL(111); LL(115); LL(119); LL(123); LL(127) ]  )

ltable = Array(  [[LL(16); LL(52); LL(56); LL(70); LL(83); LL(94); LL(105); LL(0xff)] [LL(72); LL(114); LL(125); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(9); LL(15); LL(30); LL(76); LL(84); LL(126); LL(0xff)] [LL(36); LL(90); LL(103); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(20); LL(56); LL(60); LL(74); LL(87); LL(98); LL(109); LL(0xff)] [ LL(1); LL(76); LL(118); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(6); LL(13); LL(19); LL(34); LL(80); LL(88); LL(0xff)] [LL(40); LL(94); LL(107); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(24); LL(60); LL(64); LL(78); LL(91); LL(102); LL(113); LL(0xff)] [ LL(5); LL(80); LL(122); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(10); LL(17); LL(23); LL(38); LL(84); LL(92); LL(0xff)] [LL(44); LL(98); LL(111); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(28); LL(64); LL(68); LL(82); LL(95); LL(106); LL(117); LL(0xff)] [ LL(9); LL(84); LL(126); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(10); LL(14); LL(21); LL(27); LL(42); LL(88); LL(96); LL(0xff)] [LL(48); LL(102); LL(115); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(32); LL(68); LL(72); LL(86); LL(99); LL(110); LL(121); LL(0xff)] [ LL(2); LL(13); LL(88); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(14); LL(18); LL(25); LL(31); LL(46); LL(92); LL(100); LL(0xff)] [LL(52); LL(106); LL(119); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(36); LL(72); LL(76); LL(90); LL(103); LL(114); LL(125); LL(0xff)] [ LL(6); LL(17); LL(92); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(18); LL(22); LL(29); LL(35); LL(50); LL(96); LL(104); LL(0xff)] [LL(56); LL(110); LL(123); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(40); LL(76); LL(80); LL(94); LL(107); LL(118); LL(0xff)] [LL(10); LL(21); LL(96); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(22); LL(26); LL(33); LL(39); LL(54); LL(100); LL(108); LL(0xff)] [LL(60); LL(114); LL(127); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(44); LL(80); LL(84); LL(98); LL(111); LL(122); LL(0xff)] [LL(14); LL(25); LL(100); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(26); LL(30); LL(37); LL(43); LL(58); LL(104); LL(112); LL(0xff)] [ LL(3); LL(118); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(9); LL(48); LL(84); LL(88); LL(102); LL(115); LL(126); LL(0xff)] [LL(18); LL(29); LL(104); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(30); LL(34); LL(41); LL(47); LL(62); LL(108); LL(116); LL(0xff)] [ LL(7); LL(122); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(13); LL(52); LL(88); LL(92); LL(106); LL(119); LL(0xff)] [LL(22); LL(33); LL(108); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(34); LL(38); LL(45); LL(51); LL(66); LL(112); LL(120); LL(0xff)] [LL(11); LL(126); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(17); LL(56); LL(92); LL(96); LL(110); LL(123); LL(0xff)] [LL(26); LL(37); LL(112); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(38); LL(42); LL(49); LL(55); LL(70); LL(116); LL(124); LL(0xff)] [ LL(2); LL(15); LL(76); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(10); LL(21); LL(60); LL(96); LL(100); LL(114); LL(127); LL(0xff)] [LL(30); LL(41); LL(116); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(42); LL(46); LL(53); LL(59); LL(74); LL(120); LL(0xff)] [ LL(6); LL(19); LL(80); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(3); LL(14); LL(25); LL(100); LL(104); LL(118); LL(0xff); LL(0xff)] [LL(34); LL(45); LL(120); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(4); LL(46); LL(50); LL(57); LL(63); LL(78); LL(124); LL(0xff)] [LL(10); LL(23); LL(84); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(7); LL(18); LL(29); LL(104); LL(108); LL(122); LL(0xff); LL(0xff)] [LL(38); LL(49); LL(124); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(8); LL(50); LL(54); LL(61); LL(67); LL(82); LL(0xff)] [LL(14); LL(27); LL(88); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(11); LL(22); LL(33); LL(108); LL(112); LL(126); LL(0xff); LL(0xff)] [ LL(0); LL(42); LL(53); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(4); LL(12); LL(54); LL(58); LL(65); LL(71); LL(86); LL(0xff)] [LL(18); LL(31); LL(92); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(15); LL(26); LL(37); LL(76); LL(112); LL(116); LL(0xff)] [ LL(4); LL(46); LL(57); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(8); LL(16); LL(58); LL(62); LL(69); LL(75); LL(90); LL(0xff)] [LL(22); LL(35); LL(96); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(19); LL(30); LL(41); LL(80); LL(116); LL(120); LL(0xff)] [ LL(8); LL(50); LL(61); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(12); LL(20); LL(62); LL(66); LL(73); LL(79); LL(94); LL(0xff)] [LL(26); LL(39); LL(100); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(10); LL(23); LL(34); LL(45); LL(84); LL(120); LL(124); LL(0xff)] [LL(12); LL(54); LL(65); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(16); LL(24); LL(66); LL(70); LL(77); LL(83); LL(98); LL(0xff)] [LL(30); LL(43); LL(104); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(14); LL(27); LL(38); LL(49); LL(88); LL(124); LL(0xff)] [LL(16); LL(58); LL(69); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(20); LL(28); LL(70); LL(74); LL(81); LL(87); LL(102); LL(0xff)] [LL(34); LL(47); LL(108); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(4); LL(18); LL(31); LL(42); LL(53); LL(92); LL(0xff)] [LL(20); LL(62); LL(73); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(24); LL(32); LL(74); LL(78); LL(85); LL(91); LL(106); LL(0xff)] [LL(38); LL(51); LL(112); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(4); LL(8); LL(22); LL(35); LL(46); LL(57); LL(96); LL(0xff)] [LL(24); LL(66); LL(77); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(28); LL(36); LL(78); LL(82); LL(89); LL(95); LL(110); LL(0xff)] [LL(42); LL(55); LL(116); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(8); LL(12); LL(26); LL(39); LL(50); LL(61); LL(100); LL(0xff)] [LL(28); LL(70); LL(81); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(32); LL(40); LL(82); LL(86); LL(93); LL(99); LL(114); LL(0xff)] [LL(46); LL(59); LL(120); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(12); LL(16); LL(30); LL(43); LL(54); LL(65); LL(104); LL(0xff)] [LL(32); LL(74); LL(85); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(36); LL(90); LL(103); LL(118); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(50); LL(63); LL(124); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(16); LL(20); LL(34); LL(47); LL(58); LL(69); LL(108); LL(0xff)] [LL(36); LL(78); LL(89); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(40); LL(94); LL(107); LL(122); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(54); LL(67); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(20); LL(24); LL(38); LL(51); LL(62); LL(73); LL(112); LL(0xff)] [LL(40); LL(82); LL(93); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(44); LL(98); LL(111); LL(126); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(4); LL(58); LL(71); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(24); LL(28); LL(42); LL(55); LL(66); LL(77); LL(116); LL(0xff)] [LL(44); LL(86); LL(97); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(48); LL(102); LL(115); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(8); LL(62); LL(75); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(28); LL(32); LL(46); LL(59); LL(70); LL(81); LL(120); LL(0xff)] [LL(48); LL(90); LL(101); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(52); LL(106); LL(119); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(12); LL(66); LL(79); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(32); LL(36); LL(50); LL(63); LL(74); LL(85); LL(124); LL(0xff)] [LL(52); LL(94); LL(105); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(10); LL(56); LL(110); LL(123); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(16); LL(70); LL(83); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(36); LL(40); LL(54); LL(67); LL(78); LL(89); LL(0xff)] [LL(56); LL(98); LL(109); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(14); LL(60); LL(114); LL(127); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(20); LL(74); LL(87); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(4); LL(40); LL(44); LL(58); LL(71); LL(82); LL(93); LL(0xff)] [LL(60); LL(102); LL(113); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(3); LL(18); LL(72); LL(114); LL(118); LL(125); LL(0xff); LL(0xff)] [LL(24); LL(78); LL(91); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(8); LL(44); LL(48); LL(62); LL(75); LL(86); LL(97); LL(0xff)] [LL(64); LL(106); LL(117); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(7); LL(22); LL(76); LL(118); LL(122); LL(0xff); LL(0xff)] [LL(28); LL(82); LL(95); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [LL(12); LL(48); LL(52); LL(66); LL(79); LL(90); LL(101); LL(0xff)] [LL(68); LL(110); LL(121); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(11); LL(26); LL(80); LL(122); LL(126); LL(0xff); LL(0xff)] [LL(32); LL(86); LL(99); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] ] )

ltable_inverse = Array(  [[ LL(53); LL(55); LL(72); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(5); LL(20); LL(90); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(15); LL(102); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(3); LL(31); LL(90); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(57); LL(59); LL(76); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(9); LL(24); LL(94); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(19); LL(106); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(7); LL(35); LL(94); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(61); LL(63); LL(80); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(9); LL(13); LL(28); LL(98); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(23); LL(110); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(11); LL(39); LL(98); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(65); LL(67); LL(84); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(13); LL(17); LL(32); LL(102); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(27); LL(114); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(3); LL(15); LL(20); LL(43); LL(102); LL(0xff); LL(0xff)] [ LL(69); LL(71); LL(88); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(17); LL(21); LL(36); LL(106); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(31); LL(118); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(7); LL(19); LL(24); LL(47); LL(106); LL(0xff); LL(0xff)] [ LL(73); LL(75); LL(92); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(21); LL(25); LL(40); LL(110); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(35); LL(122); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(9); LL(11); LL(23); LL(28); LL(51); LL(110); LL(0xff); LL(0xff)] [ LL(77); LL(79); LL(96); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(25); LL(29); LL(44); LL(114); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(9); LL(39); LL(126); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(13); LL(15); LL(27); LL(32); LL(55); LL(114); LL(0xff); LL(0xff)] [ LL(81); LL(83); LL(100); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(29); LL(33); LL(48); LL(118); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(13); LL(43); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(17); LL(19); LL(31); LL(36); LL(59); LL(118); LL(0xff)] [ LL(85); LL(87); LL(104); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(33); LL(37); LL(52); LL(122); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(17); LL(47); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(5); LL(21); LL(23); LL(35); LL(40); LL(63); LL(122); LL(0xff)] [ LL(89); LL(91); LL(108); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(9); LL(37); LL(41); LL(56); LL(126); LL(0xff); LL(0xff); LL(0xff)] [ LL(10); LL(21); LL(51); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(9); LL(25); LL(27); LL(39); LL(44); LL(67); LL(126); LL(0xff)] [ LL(93); LL(95); LL(112); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(13); LL(41); LL(45); LL(60); LL(0xff); LL(0xff); LL(0xff)] [ LL(14); LL(25); LL(55); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(2); LL(13); LL(29); LL(31); LL(43); LL(48); LL(71); LL(0xff)] [ LL(97); LL(99); LL(116); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(17); LL(45); LL(49); LL(64); LL(0xff); LL(0xff); LL(0xff)] [ LL(18); LL(29); LL(59); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(6); LL(17); LL(33); LL(35); LL(47); LL(52); LL(75); LL(0xff)] [LL(101); LL(103); LL(120); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(10); LL(21); LL(49); LL(53); LL(68); LL(0xff); LL(0xff); LL(0xff)] [ LL(22); LL(33); LL(63); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(10); LL(21); LL(37); LL(39); LL(51); LL(56); LL(79); LL(0xff)] [LL(105); LL(107); LL(124); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(14); LL(25); LL(53); LL(57); LL(72); LL(0xff); LL(0xff); LL(0xff)] [ LL(26); LL(37); LL(67); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(14); LL(25); LL(41); LL(43); LL(55); LL(60); LL(83); LL(0xff)] [ LL(0); LL(109); LL(111); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(18); LL(29); LL(57); LL(61); LL(76); LL(0xff); LL(0xff); LL(0xff)] [ LL(30); LL(41); LL(71); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(18); LL(29); LL(45); LL(47); LL(59); LL(64); LL(87); LL(0xff)] [ LL(4); LL(113); LL(115); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(22); LL(33); LL(61); LL(65); LL(80); LL(0xff); LL(0xff); LL(0xff)] [ LL(34); LL(45); LL(75); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(22); LL(33); LL(49); LL(51); LL(63); LL(68); LL(91); LL(0xff)] [ LL(8); LL(117); LL(119); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(26); LL(37); LL(65); LL(69); LL(84); LL(0xff); LL(0xff); LL(0xff)] [ LL(38); LL(49); LL(79); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(26); LL(37); LL(53); LL(55); LL(67); LL(72); LL(95); LL(0xff)] [ LL(12); LL(121); LL(123); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(30); LL(41); LL(69); LL(73); LL(88); LL(0xff); LL(0xff); LL(0xff)] [ LL(42); LL(53); LL(83); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(30); LL(41); LL(57); LL(59); LL(71); LL(76); LL(99); LL(0xff)] [ LL(16); LL(125); LL(127); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(34); LL(45); LL(73); LL(77); LL(92); LL(0xff); LL(0xff); LL(0xff)] [ LL(46); LL(57); LL(87); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(34); LL(45); LL(61); LL(63); LL(75); LL(80); LL(103); LL(0xff)] [ LL(1); LL(3); LL(20); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(38); LL(49); LL(77); LL(81); LL(96); LL(0xff); LL(0xff); LL(0xff)] [ LL(50); LL(61); LL(91); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(38); LL(49); LL(65); LL(67); LL(79); LL(84); LL(107); LL(0xff)] [ LL(5); LL(7); LL(24); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(42); LL(53); LL(81); LL(85); LL(100); LL(0xff); LL(0xff); LL(0xff)] [ LL(54); LL(65); LL(95); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(42); LL(53); LL(69); LL(71); LL(83); LL(88); LL(111); LL(0xff)] [ LL(9); LL(11); LL(28); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(46); LL(57); LL(85); LL(89); LL(104); LL(0xff); LL(0xff); LL(0xff)] [ LL(58); LL(69); LL(99); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(46); LL(57); LL(73); LL(75); LL(87); LL(92); LL(115); LL(0xff)] [ LL(13); LL(15); LL(32); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(50); LL(61); LL(89); LL(93); LL(108); LL(0xff); LL(0xff); LL(0xff)] [ LL(62); LL(73); LL(103); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(50); LL(61); LL(77); LL(79); LL(91); LL(96); LL(119); LL(0xff)] [ LL(17); LL(19); LL(36); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(54); LL(65); LL(93); LL(97); LL(112); LL(0xff); LL(0xff); LL(0xff)] [ LL(66); LL(77); LL(107); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(54); LL(65); LL(81); LL(83); LL(95); LL(100); LL(123); LL(0xff)] [ LL(21); LL(23); LL(40); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(58); LL(69); LL(97); LL(101); LL(116); LL(0xff); LL(0xff); LL(0xff)] [ LL(70); LL(81); LL(111); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(58); LL(69); LL(85); LL(87); LL(99); LL(104); LL(127); LL(0xff)] [ LL(25); LL(27); LL(44); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(62); LL(73); LL(101); LL(105); LL(120); LL(0xff); LL(0xff); LL(0xff)] [ LL(74); LL(85); LL(115); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(3); LL(62); LL(73); LL(89); LL(91); LL(103); LL(108); LL(0xff)] [ LL(29); LL(31); LL(48); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(66); LL(77); LL(105); LL(109); LL(124); LL(0xff); LL(0xff); LL(0xff)] [ LL(78); LL(89); LL(119); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(7); LL(66); LL(77); LL(93); LL(95); LL(107); LL(112); LL(0xff)] [ LL(33); LL(35); LL(52); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(70); LL(81); LL(109); LL(113); LL(0xff); LL(0xff); LL(0xff)] [ LL(82); LL(93); LL(123); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(11); LL(70); LL(81); LL(97); LL(99); LL(111); LL(116); LL(0xff)] [ LL(37); LL(39); LL(56); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(LL(4)); LL(LL(74)); LL(85); LL(113); LL(117); LL(0xff); LL(0xff); LL(0xff)] [ LL(86); LL(97); LL(127); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(15); LL(74); LL(85); LL(101); LL(103); LL(115); LL(120); LL(0xff)] [ LL(41); LL(43); LL(60); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(8); LL(78); LL(89); LL(117); LL(121); LL(0xff); LL(0xff); LL(0xff)] [ LL(3); LL(90); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(19); LL(78); LL(89); LL(105); LL(107); LL(119); LL(124); LL(0xff)] [ LL(45); LL(47); LL(64); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(12); LL(82); LL(93); LL(121); LL(125); LL(0xff); LL(0xff); LL(0xff)] [ LL(7); LL(94); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(0); LL(23); LL(82); LL(93); LL(109); LL(111); LL(123); LL(0xff)] [ LL(49); LL(51); LL(68); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(1); LL(16); LL(86); LL(97); LL(125); LL(0xff); LL(0xff); LL(0xff)] [ LL(11); LL(98); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff); LL(0xff)] [ LL(4); LL(27); LL(86); LL(97); LL(113); LL(115); LL(127); LL(0xff)] ])

ROUNDS = 32
BLOCK_SIZE = 16
PHI = 0x9E3779B9

beg = 1

function makekey(key::Array{UInt8})
    w = zeros(Int64, 4 * (ROUNDS + 1))
    offset = 1;
    limit = length(key)

    for i in 1:limit
        w[Int64(floor((i - 1) / 4)) + 1] |= (Int64(key[i]) & Int64(0xff)) << ((i % 4) * 8)
    end


    i = limit + 1
    if( i <= 8)
        w[(i = i + 1) - 1] = 1
    end


    t;
    j = 1;
    for i in 9:16
        t = w[j] $ w[i-5] $ w[i-3] $ w[i-1] $ PHI $ Int64(j)
        j += 1
        w[i] = ((t << 11) | tripleshift(t, 21) )
    end
    j = 9;
    for i in 1:8
        w[i] = w[(j = j + 1) - 1]
    end

    limit = 4 * (ROUNDS + 1)

    for j in i+1:limit
        t = w[j-8] $ w[j-5] $ w[j-3] $ w[j-1] $ PHI $ j;
        w[j] = t << Int32(11) | t >>> Int32(21);
    end

    k = zeros(Int64, limit)
    for i in 1:ROUNDS
        box = (ROUNDS + 3 - i) % ROUNDS
        a = w[4*i    ]
        b = w[4*i + 1]
        c = w[4*i + 2]
        d = w[4*i + 3]
        for j in 1:32
            inp = Int64(getbit(a, j - 1)) | Int64(getbit(b, j - 1 )) << 1 | Int64(getbit(c, j - 1)) << 2 | Int64(getbit(d, j -1)) << 3  
            out = s(box, inp)
            k[4*i    ] |= Int64(getbit(out, 0)) << j
            k[4*i + 1] |= Int64(getbit(out, 1)) << j
            k[4*i + 2] |= Int64(getbit(out, 2)) << j
            k[4*i + 3] |= Int64(getbit(out, 3)) << j
        end
    end
    K = zeros(Int64, 4, ROUNDS + 1)
    offset = 1
    for i in 1:ROUNDS+1
        K[1,i] = k[(offset = offset + 1) - 1]
        K[2,i] = k[(offset = offset + 1) - 1]
        K[3,i] = k[(offset = offset + 1) - 1]
        K[4,i] = k[(offset = offset + 1) - 1]
    end
    for i in 1:ROUNDS+1
       K[1:4, i] = ip(K[1:4, i]) 
    end
    return K
end

function blockencrypt(inp::Array{UInt8}, inOffset, sessionKey)
    Khat = sessionKey

    x = (inp[(inOffset = inOffset + 1) - 1] & Int64(Int64(0xFF))) | (inp[(inOffset = inOffset + 1) - 1] & Int64(Int64(0xFF))) <<  8 |  (inp[(inOffset = inOffset + 1) - 1] &  Int64(Int64(0xFF))) << 16 | (inp[(inOffset = inOffset + 1) - 1] &  Int64(Int64(0xFF))) << 24, (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) <<  8 |       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 16 | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 24,       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) <<  8 |       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 16 | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 24,       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) <<  8 |       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 16 | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 24 
    Bhat = ip(x)
    for i in 0:ROUNDS-1
        Bhat = r(i, Bhat, Khat) 
    end
    x = fp(Bhat)
    a = x[1]
    b = x[2]
    c = x[3]
    d = x[4]
    result = [
        tou8(a), tou8(a >>> 8), tou8(a >>> 16), tou8(a >>> 24),
            tou8(b), tou8(b >>> 8), tou8(b >>> 16), tou8(b >>> 24),
            tou8(c), tou8(c >>> 8), tou8(c >>> 16), tou8(c >>> 24),
            tou8(d), tou8(d >>> 8), tou8(d >>> 16), tou8(d >>> 24)]

    return result
end

function tou8(x)
    return convert(UInt8, x & 0xff) 
end

function blockdecrypt(inp::Array{UInt8}, inOffset, sessionKey)

    Khat = sessionKey
    x = (inp[(inOffset = inOffset + 1) - 1] & Int64(Int64(0xFF))) | (inp[(inOffset = inOffset + 1) - 1] & Int64(Int64(0xFF))) <<  8 |  (inp[(inOffset = inOffset + 1) - 1] &  Int64(Int64(0xFF))) << 16 | (inp[(inOffset = inOffset + 1) - 1] &  Int64(Int64(0xFF))) << 24, (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) <<  8 |       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 16 | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 24,       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) <<  8 |       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 16 | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 24,       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) <<  8 |       (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 16 | (inp[(inOffset = inOffset + 1) - 1] & Int64(0xFF)) << 24 
    Bhat = fpinverse(x)
    for i in ROUNDS-1:-1:0
        Bhat = rinverse(i, Bhat, Khat)
    end
    x = ipinverse(Bhat);
    a = x[1]
    b = x[2]
    c = x[3]
    d = x[4]
    result = [
        tou8(a), tou8(a >>> 8), tou8(a >>> 16), tou8(a >>> 24),
            tou8(b), tou8(b >>> 8), tou8(b >>> 16), tou8(b >>> 24),
            tou8(c), tou8(c >>> 8), tou8(c >>> 16), tou8(c >>> 24),
            tou8(d), tou8(d >>> 8), tou8(d >>> 16), tou8(d >>> 24)]

    return result
end



function getbit(x::Integer, i::Integer)
    ret = tripleshift(x,i) & 0x01
    return ret
end

function getbit(x::Int64, i::Int64)
    ret = tripleshift(x,i) & 0x01
    return ret
end

function getbit(x::UInt8, i::Int64)
    ret = tripleshift(x,i) & 0x01
    return ret
end

function getbit(x, i)
    return Int64(x[beg + div(i, 32)] >>> (i % 32)) & Int64(0x01)
end

function getnibble(x, i)
    return (x >>> (4 * i)) & Int64(0x0f)
end

function ip(x)
    return permutate(iptable,x)
end

function ipinverse(x)
    return permutate(fptable, x)
end

function fp(x)
    return permutate(fptable, x)
end

function fpinverse(x)
    return permutate(iptable, x)
end

function setbit(x, i, v)
    if ((v & 0x01) == 1)
        x[beg + div(i, 32)] |= Int64(1) << (i % 32) 
    else
        x[beg + div(i, 32)] &= ~(Int64(1) << (i % 32)) 
    end
    return x
end

function permutate (T, x)
    result = zeros(Int64, 4)
    for i in 1:128
        bit = getbit(x, T[i] & 0x7F)
        result = setbit(result, i - 1, getbit(x, T[i] & 0x7F))
    end
    return result
end

function xor128(x, y)
    a = x[1] $ y[1], x[2] $ y[2], x[3] $ y[3], x[4] $ y[4]
    return a
end

function s(box, x)
    return sbox[beg + x, beg + box] & 0x0f
end

function sinverse(box, x)
    return inverse_sbox[beg + x, beg + box] & 0x0f
end

function shat(box, x)
    result = zeros(Int64, 4)
    for i in 1:4
        for nibble in 0:7
            result[i] |= Int64(s(box, getnibble(x[i], nibble))) << (nibble * 4)
        end
    end
    return result
end

function shatinverse(box, x)
    result = zeros(Int64, 4)
    for i in 1:4
        for nibble in 0:7
            result[i] |= Int64(sinverse(box, getnibble(x[i], nibble))) << (nibble * 4) 
        end
    end
    return result
end


function lt(x)
    return transform(ltable, x)
end

function ltinverse(x)
    return transform(ltable_inverse, x)
end


function transform(T, x)
    j = 1
    b = 0
    result = zeros(Int64, 4)
    for i in 1:128
        b = 0
        j = 1
        while(T[j, i] != 0xFF)
            b $= Int64(getbit(x, T[j, i] & Int64(0x7F)))
            j += 1
        end
        result = setbit(result, i - 1, b)
    end
    return result
end

function r(i, Bhati, Khat)
    xored = xor128(Bhati, Khat[1:4, beg+i])
    shati = shat(i, xored)
    BahtiPlus1 = zeros(Int64, 0)
    if((0 <= i) && (i <= ROUNDS - 2))
        BhatiPlus1 = lt(shati)
    elseif(i == ROUNDS - 1)
        BhatiPlus1 = xor128(shati, Khat[1:4, ROUNDS])
    end
    return BhatiPlus1
end

function rinverse(i, BhatiPlus1, Khat)
    shati = zeros(Int64, 4)
    if ((0 <= i) && (i <= ROUNDS - 2))
        shati = ltinverse(BhatiPlus1)
    elseif (i == ROUNDS - 1)
        shati = xor128(BhatiPlus1, Khat[1:4, ROUNDS])
    end
    #println("shati inv:", shati)
    xored = shatinverse(i, shati)
    #println("xored inv:", xored)
    Bhati = xor128(xored, Khat[1:4, beg+i])

    return Bhati
end

function stringtobytearray(str::ASCIIString)
    ret = zeros(UInt8, 0)
    for i in str
        push!(ret, convert(UInt8, i))
    end
    return ret
end

function bytearraytostring(bytes::Array{UInt8})
    ret = ""
    for i in bytes 
        ret = string(ret, Char(i))
    end
    return ret
end

function encrypt(block::Array{UInt8}, key::Array{Int64, 2})
    return blockencrypt(block, 1, key)
end

function decrypt(block::Array{UInt8}, key::Array{Int64, 2})
    return blockdecrypt(block, 1, key)
end

end
