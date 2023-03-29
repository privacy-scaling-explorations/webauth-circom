/*
  signal input pubkey[2][k]; 
  signal input r[k];
  signal input s[k];

  signal input challenge[max_challenge]; // options.challenge

  signal input client_data_json[max_client_json]; 
  signal input challenge_offset; // where the challenge is in the json, C.challenge
  signal input authenticator_data[max_auth_data]; // 37 bytes or more, just do an array of 37*8 bits, decoded
*/

export async function generate_inputs() {
    /* SIGNATURE */
    const signature = "MEQCIE3GC4J3W4iKrKk1BmjDMOB8awXNBcBg1yWNzlGVPzi2AiAiIoN_rZf1o8BXP4OsR6PTsZx6poe77ymy7ddRw8Xyig";
    let sig = BigInt("0x" + Buffer.from(signature, "base64").toString("hex"));

    console.log("decoded sig")
    console.log(sig)

    // TODO: might need base64url conversion stuff
    const client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiR0cyRGdLNkFPelJJOUJZdGNVUGdkaTFZRFVlVlVVQnEtVW1GeFpCbU9YSSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9";
    let client_data = Buffer.from(client_data_json, "base64")
}