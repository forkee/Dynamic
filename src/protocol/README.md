# DynamicX 2.0 Protocol

```
/**
 * Copyright 2017 Everybody and Nobody (Empinel/Plaxton)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject 
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE 
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
 ```
 
 The DynamicX Protocol is the culmination of the integration of the Syscoin Protocol (Certificates, Marketplace, Messaging) and the 
 Fluid Protocol as developed by @plaxton, this README will be pertaining mostly to the Fluid Protocol that is currently under development
 and in the **alpha** phase.
 
 ## Fluid Autonomous Monetary Regulation Protocol
 
 Fluid is a regulation protcol that allows the thumbrule management of the Dynamic Network by the usage of simple command token signage and the psudeo-usage of the scripting language within the Dynamic Protocol
 
 * Fluid allows for the creation of Dynamic using the `OP_MINT` opcode transaction that allows for coins to be issued to particular addresses with a specific quantity not more than 10% of the Network's Supply of Dynamic per issuance transaction
 * Fluid allows for the trackable destruction of Dynamic using the `OP_DESTROY` opcode transaction that allows for coins to be verifiably destroyed with information about coins burnt be made available as by a CChain Parameter
 * Fluid allows for the transferrance of master rights by using the `OP_DROPLET` opcode transaction that allows for the sovreign address to be changed in the network, when the genesis block is made - it does **not** need approval from the previous address as there wasn't one but beyound the genesis block, any transferrance will require approval from the previous sovereign address
 * Fluid allows for the alteration of Dynode and Mining Rewards by using the `OP_REWARD_DYNODE` and `OP_REWARD_MINING` opcode transactions respectively with effect lasting no more than a block after such a request is made, **such is subject to change**
 * Fluid allows for the blocking of transactions from addresses by using the `OP_STERILIZE` opcode transaction that will add unto a vector containing all the blocked addresses as part of the block structure, **9this is permanent and no blocked address can be unblocked**
 * The protocol does track the amount of total supply (taken from Sequence) with modifications to accomodate the burning of coins with individual tracking of the same
 
