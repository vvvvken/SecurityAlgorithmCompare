package vken.comparer;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by vkenchen on 17/3/10.
 */
public class Comparer {

    public class CellOperationResult {
        String operationName;
        int loopTimes;
        long consumeMillSenconds;

        @Override
        public String toString() {
            String str = "算法名：" + operationName + "\t\t 循环次数：" + loopTimes + "\t\t总耗时：" + consumeMillSenconds;
            return str;
        }
    }


    private List<ICompareCell> cellList = new ArrayList<ICompareCell>();

    public void addCell(ICompareCell cell) {
        cellList.add(cell);
    }


    public Map<String, CellOperationResult> compare(byte[] data, int loopTimes) {
        if (loopTimes < 0)
            return null;

        if (cellList.size() <= 0)
            return null;

        Map<String, CellOperationResult> result = new HashMap<String, CellOperationResult>();
        for (int i = 0; i < cellList.size(); i++) {

            ICompareCell cell = cellList.get(i);

            CellOperationResult cellResult = new CellOperationResult();
            cellResult.operationName = cell.cellName();
            cellResult.loopTimes = loopTimes;
            cellResult.consumeMillSenconds = doCellOperation(data, cell, loopTimes);
            result.put(cell.cellName(), cellResult);
        }

        printCompareResult(result, loopTimes);

        return result;
    }

    public void printCompareResult(Map<String, CellOperationResult> result, int loopTimes) {
        for (String key : result.keySet()) {
            CellOperationResult cellResult = result.get(key);
            System.out.println(cellResult.toString());
        }
    }


    public long doCellOperation(byte[] data, ICompareCell cell, int loopTimes) {
        long startTick = System.currentTimeMillis();
        for (int i = 0; i < loopTimes; i++) {
            cell.operation(data);
        }
        long endTick = System.currentTimeMillis();
        long consume = endTick - startTick;
        return consume;
    }

}
