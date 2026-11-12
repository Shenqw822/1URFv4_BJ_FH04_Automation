def compare_lists(list1, list2):
    # 检查列表2的长度是否比列表1长
    if len(list2) > len(list1):
        # 检查列表1是否是列表2的子集
        if all(item in list2 for item in list1):
            return True
        else:
            return False
    else:
        return "列表2的长度不比列表1长"

# 示例用法
list1 = [6]
list2 = [1, 3, 2, 4, 5]

result = compare_lists(list1, list2)
print(result)
