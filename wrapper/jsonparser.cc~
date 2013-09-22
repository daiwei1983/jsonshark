#include "jsonparser.h"

//We use a json message to keep detailed information of each packet. Each json message is stored as a tree here, where each item (or tree node)
//correspondes to a line in the dissected output. This item may have a chld item that contains more detailed sub-information, or a next item that 
//contains next line of output at the same level.

typedef struct item {
    struct item *chld;
    struct item *next;
    char *showName; //parsed packet information to be shown
};

//Function used to new an item
extern item *newItem() {
	item *i = (item *)malloc(sizeof(item));
	i->chld = NULL;
	i->next = NULL;
	i->showName = NULL;
	return i;
}

//Function used to free a tree of items, given a root item 
extern void freeItems(item *root) {
	if (root != NULL) {
		freeItems(root->chld);
		freeItems(root->next);
		free(root->showName);
		free(root);
	}
	return;
}

//Function used to add a next item, given the current item and the showName of the next item
extern item *addNextItem(item *i, char *s) {
	if (i == NULL) {
		i = newItem();
		i->showName = (char *)malloc(strlen(s) * sizeof(char) + 1);
		strcpy(i->showName, s);
		return i;
	}
	else {
		item *nextItem = newItem();
		nextItem->showName = (char *)malloc(strlen(s) * sizeof(char) + 1);
		strcpy(nextItem->showName, s);
		i->next = nextItem;
		return nextItem;
	}
}

//Function used to add a chld item, given the current item and showName of the chld item
extern item *addChldItem(item *i, char *s) {
	item *chldItem = newItem();
	chldItem->showName = (char *)malloc(strlen(s) * sizeof(char) + 1);
	strcpy(chldItem->showName, s);
	i->chld = chldItem;
	return chldItem;	
}

//Function used to add an item in the tree, given the root of the tree and the level of the tree to be added
extern item *addParentItem(item *root, int indent, char *s) {
	item *curItem = root;
	for(int i=0; i<indent+1; i++) {
		while(curItem->next != NULL)
			curItem = curItem->next;
		if(i != indent && curItem->chld != NULL)
			curItem = curItem->chld;
	}
	item *parentItem = newItem();
	parentItem->showName = (char *)malloc(strlen(s) * sizeof(char) + 1);
	strcpy(parentItem->showName, s);
	curItem->next = parentItem;
	return parentItem;
}

//Function used to save a tree of the items into a file as a json string.
void saveItem(item *root, FILE *fp) {
	item *curItem = root;
	while(curItem != NULL) {
		fprintf(fp, "%s", "{\n");
		fprintf(fp, "%s", "\"showname\": ");
		fprintf(fp, "%s", "\"");
		fprintf(fp, "%s", curItem->showName);
		if(curItem->chld != NULL) {
			fprintf(fp, "%s", "\",\n");
			fprintf(fp, "\"fields\": [\n");
			saveItem(curItem->chld, fp);
			fprintf(fp, "%s", "]\n");
		}
		else
			fprintf(fp, "%s", "\"\n");
		if(curItem->next != NULL)
			fprintf(fp, "%s", "},\n");
		else
			fprintf(fp, "%s", "}\n");
		curItem = curItem->next;
	}
}

//Function used to save detailed packet information into a file and the according postions of each packet in the file into another file, so as to speed up searching 
extern void saveAsJsonString(item *root, FILE *detailTmp, FILE *indexTmp) {
	if (root != NULL) {
		int position = ftell(detailTmp);
		fprintf(indexTmp, "%d", position);
		fprintf(detailTmp, "%s","{\n\"protocols\": [\n");
		saveItem(root, detailTmp);
		fprintf(detailTmp, "]\n}\n");
		fflush(detailTmp);
		position = ftell(detailTmp);
		fprintf(indexTmp, ",%d\n", position-1);
		fflush(indexTmp);
	}
	return;
}
