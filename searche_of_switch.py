from pythonping import ping

range_of_shwitches_start = "10.100.2.0"
range_of_shwitches_stop = "10.100.70.20"

l_switches = []


def gen_sw(range_of_shwitches_start, range_of_shwitches_stop):

    # range_start = [int(sw) for sw in range_of_shwitches_start.split(".")]
    # range_stop = [int(sw) for sw in range_of_shwitches_stop.split(".")]

    cur_sw = range_of_shwitches_start
    yield cur_sw
    while cur_sw != range_of_shwitches_stop:
        l_cur_sw = [int(i) for i in (cur_sw.split("."))]
        if l_cur_sw[2] >= 100:
            yield "stop"
            return
        if l_cur_sw[3] >=20:
            l_cur_sw[2], l_cur_sw[3] = l_cur_sw[2]+1, 1
            cur_sw = ".".join([str(i) for i in l_cur_sw])
            yield cur_sw
            continue
        l_cur_sw[3] = l_cur_sw[3]+1
        cur_sw = ".".join([str(i) for i in l_cur_sw])
        yield cur_sw
    return


for _ in range(2):
    cur_sw = gen_sw(range_of_shwitches_start, range_of_shwitches_stop)
    count =1
    for sw in cur_sw:
        if sw not in l_switches and ping(sw, count=1, timeout=0.01).success():
            l_switches.append(sw)
            print(f"Found {sw}!")
            count +=1
        else:
            #print(f"{sw} not found!")
            ...
    print (count)
