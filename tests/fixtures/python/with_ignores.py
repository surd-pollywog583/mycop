import os

# mycop-ignore:PY-SEC-005
result = eval(user_input)  # This should NOT be reported

exec(code)  # This SHOULD be reported

os.system("ping " + host)  # mycop-ignore
