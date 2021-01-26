// SPDX-License-Identifier: MIT

pragma solidity >=0.5.3 <0.7.0;

import "./BN256G1.sol";
import "./BN256G2.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";

library BLS {
    using SafeMath for uint256;

    struct G1Point {
        uint x;
        uint y; 
    }

    struct G2Point {
        uint[2] x;
        uint[2] y; 
    }

    /**
     * @return The generator of G1.
     */
    function P1() internal pure returns (G1Point) {
        return G1Point(BN256G1.GX, BN256G1.GY);
    }

    /**
     * @return The generator of G2.
     */
    function P2() internal pure returns (G2Point) {
        return G2Point({
            x: [
                BN256G2.G2_NEG_X_RE,
                BN256G2.G2_NEG_X_IM
            ],
            y: [
                BN256G2.G2_NEG_Y_RE,
                BN256G2.G2_NEG_Y_IM
            ]
        });
    }

    function hashToG1(bytes _msg) internal pure returns (G1Point) {
        (uint x, uint y) = BN256G1.hashToTryAndIncrement(_msg);
        return G1Point(x, y);
    }

    function verifySignature(
        G2Point publicKey,
        bytes _message,
        G1Point signature
    ) internal returns (bool) {
        G1Point memory msgHash = hashToG1(_message);
        G2Point memory g2 = P2();
        bool pairingValid = BN256G1.bn256CheckPairing([
            msgHash.x,
            msgHash.y,
            publicKey.x[0],
            publicKey.x[1],
            publicKey.y[0],
            publicKey.y[1],
            signature.x,
            signature.y,
            g2.x[0],
            g2.x[1],
            g2.y[0],
            g2.y[1]
        ]);
        return pairingValid;
    }

    function aggregatePublicKey(
        G2Point[] publicKeys
    ) internal returns (G2Point) {
        G2Point aggpk;
        for(i = 0; i < publicKeys.length; i++) {
            aggpk = BN256G2.ecTwistAdd(
                aggpk.x[0],
                aggpk.x[1],
                aggpk.y[0],
                aggpk.y[1],
                publicKeys[i].x[0],
                publicKeys[i].x[1],
                publicKeys[i].y[0],
                publicKeys[i].y[1]
            );
        }
    }
}