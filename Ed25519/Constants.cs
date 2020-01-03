using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Ed25519
{
    internal static class Constants
    {
        //
        // Compiler-time constants:
        //
        internal const int BIT_LENGTH = 256;

        //
        // Run-time constants:
        //
        internal static readonly BigInteger Q = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819949");
        internal static readonly BigInteger QM2 = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819947");
        internal static readonly BigInteger QP3 = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819952");
        internal static readonly BigInteger L = BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");
        internal static readonly BigInteger D = BigInteger.Parse("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");
        internal static readonly BigInteger I = BigInteger.Parse("19681161376707505956807079304988542015446066515923890162744021073123829784752");
        internal static readonly BigInteger U_N = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819967");
        internal static readonly BigInteger TWO = new BigInteger(2);
        internal static readonly BigInteger EIGHT = new BigInteger(8);

        //
        // Pre-calculated values:
        //
        internal static readonly EdPoint B = new EdPoint
        {
            X = BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202").Mod(Q),
            Y = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960").Mod(Q),
        };

        internal static readonly BigInteger RECOVER_X_EXP = QP3 / EIGHT;
        internal static readonly BigInteger TWO_POW_BIT_LENGTH_MINUS_TWO = BigInteger.Pow(2, BIT_LENGTH - 2);
        internal static readonly BigInteger[] TWO_POW_CACHE = Enumerable.Range(0, 2 * BIT_LENGTH).Select(i => BigInteger.Pow(2, i)).ToArray();
    }
}
