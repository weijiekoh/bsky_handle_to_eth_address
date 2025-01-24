import { Buffer } from 'buffer';
import * as ethers from "ethers";
import multibase from 'multibase';

const PDS_URL = "https://api.bsky.app"
const RESOLVE_HANDLE_PATH = "/xrpc/com.atproto.identity.resolveHandle?handle="
const PLC_URL = "https://plc.directory/"

const lookup = async () => {
    const handleOrDid = document.getElementById('handle_or_did').value.trim();
    const info_or_error = document.getElementById('info_or_error');

    if (!handleOrDid) {
        info_or_error.textContent = 'Please enter a handle or DID.';
        return;
    }

    info_or_error.textContent = 'Looking up...';
    let handle;
    let did;
    //if (handle_or_did.startswith("did:"): did = handle_or_did
    if (handleOrDid.startsWith("did:")) {
        did = handleOrDid;
    } else {
        handle = handleOrDid;
        // Look up DID
        const req = await fetch(PDS_URL + RESOLVE_HANDLE_PATH + handle)
        const json = await req.json()
        if ("did" in json) {
            did = json["did"]
        } else {
            info_or_error.textContent = 'Invalid handle: ' + handle
            return
        }
    }

    // Look up repo
    const req = await fetch(PLC_URL + did)
    const repo = await req.json()

    // Fetch their service endpoint(s)
    const endpoints = []
    if (Object.keys(repo).includes("service")) {
        for (const service of repo["service"]) {
            if (Object.keys(service).includes("serviceEndpoint")) {
                endpoints.push(service["serviceEndpoint"])
            }
        }
    } else {
        info_or_error.textContent = 'Warning: could not find the "service" field in the repo description. Be careful!'
    }

    let isHosted = false
    if (endpoints.length == 0) {
        info_or_error.textContent = 'Warning: the user\'s repo does not list any service endpoints. Be careful!'
    } else {
        for (const endpoint of endpoints) {
            if (endpoint.endsWith("host.bsky.network")) {
                isHosted = true
                break
            }
        }
    }
    if (isHosted) {
        info_or_error.textContent = 'Warning: the user\'s repo is probably hosted by Bluesky PBC, and most likely don\'t own their private key(s). Do not send funds to them if you are unsure.'
    } else {
        info_or_error.textContent = 'Warning: only send funds to this user if you are sure they exclusively own their private key(s).'
    }
    /*
        multibase_keys = []
        if "verificationMethod" in json.keys():
            pass
        else:
            raise ValueError("Unable to query " + PLC_URL + did)

        for key in json["verificationMethod"]:
            if "publicKeyMultibase" in key.keys():
                multibase_keys.append(key["publicKeyMultibase"])
    */

    const multibase_keys = []
    for (const key of repo["verificationMethod"]) {
        if ("publicKeyMultibase" in key) {
            multibase_keys.push(key["publicKeyMultibase"])
        }
    }

    const ethAddresses = []
    for (const key of multibase_keys) {
        const bytes = multibase.decode(key)
        const pubkeyHex = Buffer.from(bytes).toString('hex')

        if (!pubkeyHex.startsWith("e701")) {
            info_or_error.textContent = 'Invalid public key: ' + pubkeyHex
            return
        }

        const pubkeyHexSliced = pubkeyHex.slice(4)
        const add = ethers.computeAddress('0x' + pubkeyHexSliced)
        ethAddresses.push(add)
    }

    if (ethAddresses.length == 0) {
        info_or_error.textContent = 'No Ethereum addresses found for ' + handleOrDid
        return
    } else if (ethAddresses.length == 1) {
        info_or_error.textContent = 'Ethereum address: ' + ethAddresses[0]
    } else {
        let txt = ""
        for (const add of ethAddresses) {
            txt += add + ", "
        }
        txt = txt.slice(0, -2)
        info_or_error.textContent = 'Ethereum addresses:\n' + txt
    }
}

const main = async () => {
    const lookupBtn = document.getElementById('lookup');
    const input = document.getElementById('handle_or_did');
    lookupBtn.addEventListener('click', lookup);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            lookup()
        }
    })
}

main()
