// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
 
import {Script} from "../lib/forge-std/src/Script.sol";
import {console2} from "../lib/forge-std/src/console2.sol";
import {ClaimVault} from "../src/ClaimVault.sol";
 
contract ZeroBaseScript is Script {
    address constant ZBT = 0x1a44076050125825900e736c501f859c50fE728c;
    address signer = address(0xffff);
    address executor = address(0xffff);
    address owner;

    function run() public {
        // Setup
        uint256 privateKey = vm.envUint("PRIVATE_KEY_MAIN");//Main
        vm.startBroadcast(privateKey);

        owner = vm.addr(privateKey);
        ClaimVault claimVault = new ClaimVault(address(ZBT),signer);
    
        console2.log("ZEROBASE deployed at:", address(claimVault));

        vm.stopBroadcast();
    }
}
