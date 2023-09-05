// SPDX-License-Identifier: MIT

pragma solidity >=0.5.3 <0.7.0;
pragma experimental ABIEncoderV2;

import "./BN256G1.sol";
import "./BN256G2.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";

contract BLS {
    using SafeMath for uint256;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    /**
     * @return The generator of G1.
     */
    function P1() internal pure returns (G1Point memory) {
        return G1Point(BN256G1.GX, BN256G1.GY);
    }

    /**
     * @return The generator of G2.
     */
    function P2() internal pure returns (G2Point memory) {
        return
            G2Point({
                x: [BN256G2.G2_NEG_X_RE, BN256G2.G2_NEG_X_IM],
                y: [BN256G2.G2_NEG_Y_RE, BN256G2.G2_NEG_Y_IM]
            });
    }

    function hashToG1(bytes calldata _msg)
        internal
        pure
        returns (G1Point memory)
    {
        (uint256 x, uint256 y) = BN256G1.hashToTryAndIncrement(_msg);
        return G1Point(x, y);
    }

    function verifySignature(
        G2Point calldata publicKey,
        bytes calldata _message,
        G1Point calldata signature
    ) public returns (bool) {
        G1Point memory msgHash = hashToG1(_message);
        G2Point memory g2 = P2();
        bool pairingValid = BN256G1.bn256CheckPairing(
            [
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
            ]
        );
        return pairingValid;
    }

    function aggregatePublicKey(G2Point[] memory publicKeys)
        public
        returns (G2Point memory)
    {
        G2Point memory aggpk;
        for (uint256 i = 0; i < publicKeys.length; i++) {
            (uint256 xx, uint256 xy, uint256 yx, uint256 yy) = BN256G2
                .ecTwistAdd(
                    aggpk.x[0],
                    aggpk.x[1],
                    aggpk.y[0],
                    aggpk.y[1],
                    publicKeys[i].x[0],
                    publicKeys[i].x[1],
                    publicKeys[i].y[0],
                    publicKeys[i].y[1]
                );
            aggpk.x[0] = xx;
            aggpk.x[1] = xy;
            aggpk.y[0] = yx;
            aggpk.y[1] = yy;
        }
        return aggpk;
    }

    function verifyAggregatedSignature(
        G2Point[] calldata publicKeys,
        bytes calldata _message,
        G1Point calldata signature
    ) public returns (bool) {
        G2Point memory publicKey = aggregatePublicKey(publicKeys);
        G1Point memory msgHash = hashToG1(_message);
        G2Point memory g2 = P2();
        bool pairingValid = BN256G1.bn256CheckPairing(
            [
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
            ]
        );
        return pairingValid;
    }
}
