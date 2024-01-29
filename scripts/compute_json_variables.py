import sys

part_1 = '{"type":"webauthn.get","challenge":"'
part_2 = '","origin":"'
part_3 = '","crossOrigin":false}'

def get_bits(field, name):
  chars = [ord(x) for x in field]
  ret_string = ''
  i = 0
  for c in field:
    bits = format(ord(c), '08b')
    for b in bits[::-1]:
      ret_string += f'  bits[{i}] = {b};\n'
      i += 1

  return f'// return {field}\nfunction get_{name}() {{\n  var bits[{i}];\n' + ret_string + '  return bits;\n}\n'

def get_bytes(field, name):
  chars = [ord(x) for x in field]
  ret_string = ''
  i = 0
  for c in field:
    ret_string += f'  bytes[{i}] = {ord(c)};\n'
    i += 1

  return f'// return {field}\nfunction get_{name}() {{\n  var bytes[{i}];\n' + ret_string + '  return bytes;\n}\n'

orig_stdout = sys.stdout

f = open("../script_outputs/webauthn_json_hardcodes.circom", 'w')
sys.stdout = f
print('pragma circom 2.1.5;\n')

print(get_bytes(part_1,'json_part_1'))
print(get_bytes(part_2,'json_part_2'))
print(get_bytes(part_3,'json_part_3'))