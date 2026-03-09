// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UAVRegistry {

    struct UAVInfo {
        bool registered;
        bool blacklisted;
        uint256 regTime;
    }

    mapping(bytes32 => UAVInfo) private registry;

    event UAVRegistered(bytes32 pid);
    event UAVBlacklisted(bytes32 pid);
    event AuthRecord(bytes32 pid, bool result, uint256 time);

    function registerUAV(bytes32 pid) public {
        require(!registry[pid].registered, "Already registered");
        registry[pid] = UAVInfo(true, false, block.timestamp);
        emit UAVRegistered(pid);
    }

    function isValidUAV(bytes32 pid) public view returns (bool) {
        return registry[pid].registered && !registry[pid].blacklisted;
    }

    function blacklistUAV(bytes32 pid) public {
        registry[pid].blacklisted = true;
        emit UAVBlacklisted(pid);
    }

    function recordAuth(bytes32 pid, bool result) public {
        emit AuthRecord(pid, result, block.timestamp);
    }
}
